import copy
import gzip
import ipaddress
import json
import re
from importlib.resources import files
from urllib.parse import quote

from jsonschema import Draft4Validator
from referencing import Registry
from referencing.exceptions import NoSuchResource

from .errors import AssistantError

DATA = files("secure_firewall_assistant") / "data"
METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def reject_reference(uri):
    raise NoSuchResource(ref=uri)


def normalize(obj):
    """Translate OpenAPI 3.0 nullable to JSON Schema without remote resolution."""
    if isinstance(obj, list):
        return [normalize(x) for x in obj]
    if not isinstance(obj, dict):
        return obj
    out = {k: normalize(v) for k, v in obj.items() if k not in {"nullable", "discriminator"}}
    if obj.get("nullable"):
        return {"anyOf": [out, {"type": "null"}]}
    return out


def classify(method: str, path: str) -> str:
    if method in {"get", "head", "options"}:
        return "read"
    if path.endswith("/deployment/deploymentrequests"):
        return "deployment"
    if path.endswith(("/assignment/policyassignments", "/devices/operational/managecertificates")) or "/assignment/policyassignments/" in path:
        return "configuration"
    if ("/operational/" in path or "/deployment/" in path or "/mappings" in path or
            "/overrides" in path or "/dynamicobjects" in path):
        return "runtime-or-special"
    if method == "post" and path.endswith("/devices/devicerecords"):
        return "configuration"
    if any(p in path for p in ("/object/", "/policy/", "/devices/devicerecords/",
                                   "/devicehapairs/ftddevicehapairs")):
        return "configuration"
    return "unreviewed-write"


class Catalog:
    def __init__(self, document: dict | None = None):
        self.doc = document or json.loads(gzip.decompress((DATA / "fmc.openapi.json.gz").read_bytes()))
        self.provenance = json.loads((DATA / "provenance.json").read_text()) if document is None else {}
        self.normalized = normalize(self.doc)
        self.registry = Registry(retrieve=reject_reference)
        self.operations = {}
        for path, item in self.doc["paths"].items():
            for method, definition in item.items():
                if method in METHODS:
                    op_id = definition["operationId"]
                    if op_id in self.operations:
                        raise AssistantError("schema_invalid", "Duplicate operation ID in schema.")
                    self.operations[op_id] = {
                        "id": op_id, "method": method, "path": path,
                        "effect": classify(method, path), "definition": definition,
                        "parameters": item.get("parameters", []) + definition.get("parameters", []),
                    }

    def resolve(self, obj: dict) -> dict:
        if "$ref" not in obj:
            return obj
        ref = obj["$ref"]
        if not ref.startswith("#/"):
            raise AssistantError("schema_invalid", "External schema references are disabled.")
        try:
            cursor = self.doc
            for part in ref[2:].split("/"):
                cursor = cursor[part.replace("~1", "/").replace("~0", "~")]
            return cursor
        except KeyError:
            raise AssistantError("schema_reference_missing", "An unresolved reference requires a maintained schema correction.", reference=ref) from None

    def get(self, op_id: str) -> dict:
        if op_id not in self.operations:
            raise AssistantError("unknown_operation", "Choose an operation from the local schema catalog.")
        return self.operations[op_id]

    def search(self, query: str = "", method: str = "", offset: int = 0, limit: int = 15,
               bulk_only: bool = False) -> dict:
        def singular(word):
            if word.endswith("ies"):
                return word[:-3] + "y"
            return word[:-1] if word.endswith("s") and not word.endswith("ss") else word

        terms = [singular(t) for t in re.findall(r"[a-z0-9]+", query.lower())]
        matches = []
        for op in self.operations.values():
            if method and op["method"] != method.lower():
                continue
            if bulk_only and not self.options(op["id"])["bulk_parameter"]:
                continue
            text = (op["id"] + " " + op["path"] + " " + op["definition"].get("description", "") +
                    " " + " ".join(op["definition"].get("tags", []))).lower()
            text += " " + " ".join(singular(t) for t in re.findall(r"[a-z0-9]+", text))
            score = sum(text.count(term) for term in terms)
            resource = next((p for p in reversed(op["path"].split("/")) if not p.startswith("{")), "")
            score += sum(100 for term in terms if term == singular(resource))
            if terms and not all(term in text for term in terms):
                continue
            matches.append((score, op))
        matches.sort(key=lambda x: (-x[0], x[1]["id"]))
        offset, limit = max(0, offset), max(1, min(30, limit))
        return {"total": len(matches), "offset": offset, "operations": [
            {**{k: o[k] for k in ("id", "method", "path", "effect")},
             "execution_options": self.options(o["id"])} for _, o in matches[offset:offset + limit]],
            "next_offset": offset + limit if offset + limit < len(matches) else None}

    def describe(self, op_id: str) -> dict:
        op = self.get(op_id)
        definition = op["definition"]
        body = self.resolve(definition["requestBody"]) if "requestBody" in definition else None
        return {"id": op_id, "method": op["method"], "path": op["path"], "effect": op["effect"],
                "description": definition.get("description", ""),
                "parameters": [self.resolve(p) for p in op["parameters"]],
                "request_body": body,
                "execution_options": self.options(op_id),
                "responses": {k: {"description": self.resolve(v).get("description"),
                                  "content": {t: {"schema": c.get("schema")} for t, c in
                                              self.resolve(v).get("content", {}).items()}}
                              for k, v in definition.get("responses", {}).items()},
                "execution_available": op["effect"] in {"read", "configuration", "deployment"},
                "notes": ["Schema coverage is not device verification.",
                          "Use describe_schema for referenced component definitions."]}

    def options(self, op_id: str) -> dict:
        """Expose capabilities for every method; never infer bulk support from a name."""
        op = self.get(op_id)
        parameters = [self.resolve(p) for p in op["parameters"]]
        query = {p["name"]: p.get("schema", {}) for p in parameters if p["in"] == "query"}
        request = self.resolve(op["definition"].get("requestBody", {}))
        media = request.get("content", {})
        schema = media.get("application/json", {}).get("schema", {})

        def accepts_array(value, seen=frozenset()):
            if "$ref" in value:
                if value["$ref"] in seen:
                    return False
                return accepts_array(self.resolve(value), seen | {value["$ref"]})
            if value.get("type") == "array":
                return True
            return any(accepts_array(v, seen) for key in ("oneOf", "anyOf") for v in value.get(key, []))

        array = accepts_array(schema)
        bulk = "bulk" in query
        return {"bulk_parameter": bulk, "array_body": array,
                "bulk_create_supported": op["method"] == "post" and bulk and array,
                "query_parameters": list(query), "request_media_types": list(media),
                "pagination": {"supported": {"offset", "limit"}.issubset(query),
                               "expanded": "expanded" in query, "filter": "filter" in query},
                "async_response_documented": "202" in op["definition"].get("responses", {}),
                "support_basis": "local_schema; confirm observed device compatibility"}

    def schema(self, name: str) -> dict:
        if name not in self.doc.get("components", {}).get("schemas", {}):
            raise AssistantError("unknown_schema", "No component schema has this name.")
        return {"name": name, "schema": self.doc["components"]["schemas"][name]}

    def validate(self, schema: dict, instance, response: bool = False) -> list:
        normalized = normalize(copy.deepcopy(schema))
        normalized["components"] = self.normalized.get("components", {})
        try:
            # No retrieval callback is installed: references cannot trigger HTTP/file access.
            validator = Draft4Validator(normalized, registry=self.registry)
            issues = list(validator.iter_errors(instance))
        except Exception:
            if response:
                return [{"code": "response_schema_unresolved"}]
            raise AssistantError("schema_validation_unavailable", "Request validation could not resolve this schema; operation blocked.") from None
        if issues and not response:
            raise AssistantError("request_validation_failed", "Request does not satisfy the operation schema.",
                                 issues=[{"path": list(e.absolute_path), "constraint": e.validator} for e in issues[:12]])
        return [{"path": list(e.absolute_path), "constraint": e.validator} for e in issues[:12]]

    def prepare(self, op_id: str, path: dict, query: dict, headers: dict, body, domain: str) -> dict:
        op = self.get(op_id)
        path = dict(path)
        if "{domainUUID}" in op["path"]:
            if "domainUUID" in path and path["domainUUID"] != domain:
                raise AssistantError("domain_mismatch", "Path domain differs from the enrolled target domain.")
            path["domainUUID"] = domain
        actual = {"path": path, "query": query, "header": headers}
        allowed = {"path": set(), "query": set(), "header": set()}
        for item in op["parameters"]:
            p = self.resolve(item)
            location, name = p["in"], p["name"]
            if location not in actual:
                raise AssistantError("unsupported_parameter", "This parameter transport is not implemented.")
            allowed[location].add(name)
            if p.get("required") and name not in actual[location]:
                raise AssistantError("missing_parameter", "A required operation parameter is missing.", parameter=name, location=location)
            if name in actual[location]:
                self.validate(p.get("schema", {}), actual[location][name])
        for location, supplied in actual.items():
            if set(supplied) - allowed[location]:
                raise AssistantError("unknown_parameter", "Only parameters declared by the operation are accepted.", location=location)
        url_path = op["path"]
        for key, value in path.items():
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:\-]+", value) or ".." in value:
                raise AssistantError("invalid_path_parameter", "Path parameters must be resource identifiers.")
            url_path = url_path.replace("{" + key + "}", quote(value, safe=""))
        request_body = op["definition"].get("requestBody")
        if request_body:
            request_body = self.resolve(request_body)
            media = request_body.get("content", {}).get("application/json")
            if media is None:
                raise AssistantError("unsupported_media", "This release executes JSON requests only.")
            if body is None and request_body.get("required"):
                raise AssistantError("missing_body", "This operation requires a JSON body.")
            if body is not None:
                self.validate(media.get("schema", {}), body)
        elif body is not None:
            raise AssistantError("unexpected_body", "This operation has no request body.")
        self.semantic(op, body, query)
        return {"method": op["method"], "path": url_path, "query": query, "headers": headers, "body": body}

    @staticmethod
    def semantic(op: dict, body, query: dict):
        if body is None:
            return
        if isinstance(body, list) and query.get("bulk") is not True:
            raise AssistantError("bulk_flag_required", "An array body requires bulk=true.")
        if query.get("bulk") is True and not isinstance(body, list):
            raise AssistantError("bulk_array_required", "bulk=true requires an array body.")
        items = body if isinstance(body, list) else [body]
        for item in items:
            if not isinstance(item, dict):
                continue
            if "/object/" in op["path"] and item.get("type") in {"Network", "Host", "Range", "FQDN"}:
                if not item.get("name") or not item.get("value"):
                    raise AssistantError("object_fields_required", "Network objects require name and value.")
                try:
                    if item["type"] == "Network":
                        ipaddress.ip_network(item["value"], strict=False)
                    elif item["type"] == "Host":
                        ipaddress.ip_address(item["value"])
                except ValueError:
                    raise AssistantError("invalid_network_value", "The object value is not a valid address or network.") from None

    def validate_response(self, op_id: str, status: int, body) -> list:
        responses = self.get(op_id)["definition"].get("responses", {})
        definition = responses.get(str(status), responses.get("default", {}))
        try:
            schema = self.resolve(definition).get("content", {}).get("application/json", {}).get("schema")
            return self.validate(schema, body, response=True) if schema else []
        except AssistantError:
            return [{"code": "response_schema_unresolved"}]
