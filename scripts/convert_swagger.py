"""Convert the supplied Swagger 2 FMC structure to the local OpenAPI 3 catalog format.

Reference data only; no URL fetching, example execution, or compatibility additions.
"""
import copy

METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def convert_swagger(document):
    if document.get("swagger") != "2.0":
        return copy.deepcopy(document)

    def rewrite(value):
        if isinstance(value, list):
            return [rewrite(v) for v in value]
        if not isinstance(value, dict):
            return value
        out = {k: rewrite(v) for k, v in value.items()}
        if "$ref" in out:
            for old, new in [("definitions", "schemas"), ("parameters", "parameters"), ("responses", "responses")]:
                out["$ref"] = out["$ref"].replace(f"#/{old}/", f"#/components/{new}/")
        if out.get("type") == "file":
            out.update(type="string", format="binary")
        return out

    doc = rewrite(document)

    def parameter(p):
        if "$ref" in p:
            return p
        if p["in"] not in {"query", "path", "header"}:
            raise ValueError("Unsupported reusable Swagger parameter location")
        result = {k: v for k, v in p.items() if k in {"name", "in", "description", "required"} or k.startswith("x-")}
        result["schema"] = {k: v for k, v in p.items() if k not in result}
        return result

    def response(r, produces):
        if "$ref" in r:
            return r
        result = {k: v for k, v in r.items() if k not in {"schema", "headers"}}
        if "schema" in r:
            result["content"] = {mime: {"schema": r["schema"]} for mime in produces}
        if "headers" in r:
            result["headers"] = {name: {"schema": header} for name, header in r["headers"].items()}
        return result

    consumes = doc.get("consumes", ["application/json"])
    produces = doc.get("produces", ["application/json"])
    paths = {}
    for path, item in doc["paths"].items():
        converted = {}
        for method, operation in item.items():
            if method not in METHODS:
                converted[method] = [parameter(p) for p in operation] if method == "parameters" else operation
                continue
            out = {k: v for k, v in operation.items() if k not in {"parameters", "responses", "consumes", "produces"}}
            params = operation.get("parameters", [])
            out["parameters"] = [parameter(p) for p in params if p.get("in") not in {"body", "formData"}]
            bodies = [p for p in params if p.get("in") == "body"]
            forms = [p for p in params if p.get("in") == "formData"]
            if len(bodies) > 1 or bodies and forms:
                raise ValueError("Ambiguous Swagger request body")
            media = operation.get("consumes", consumes)
            if bodies:
                body = bodies[0]
                out["requestBody"] = {"required": body.get("required", False),
                    "description": body.get("description", ""),
                    "content": {mime: {"schema": body["schema"]} for mime in media}}
            if forms:
                properties = {p["name"]: {k: v for k, v in p.items() if k not in {"name", "in", "required"}} for p in forms}
                schema = {"type": "object", "properties": properties}
                required = [p["name"] for p in forms if p.get("required")]
                if required:
                    schema["required"] = required
                out["requestBody"] = {"content": {mime: {"schema": schema} for mime in media}}
            out["responses"] = {code: response(r, operation.get("produces", produces)) for code, r in operation["responses"].items()}
            converted[method] = out
        paths[path] = converted
    return {"openapi": "3.0.1", "info": doc["info"], "tags": doc.get("tags", []), "paths": paths,
            "components": {"schemas": doc.get("definitions", {}),
                "parameters": {k: parameter(v) for k, v in doc.get("parameters", {}).items()},
                "responses": {k: response(v, produces) for k, v in doc.get("responses", {}).items()}}}
