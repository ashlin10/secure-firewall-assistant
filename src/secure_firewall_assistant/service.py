import hashlib
import json
import time
import uuid

from .catalog import Catalog
from .errors import AssistantError
from .evidence import Evidence, compare
from .fmc import FMC
from .security import Redactor, SecretStore
from .state import State


class Assistant:
    def __init__(self, state=None, secrets=None, client_factory=FMC):
        self.state = state or State()
        self.redactor = Redactor()
        self.secrets = secrets or SecretStore(self.redactor)
        self.catalog = Catalog()
        self.evidence = Evidence(self.state, self.redactor)
        self.clients = {}
        self.client_factory = client_factory
        self.previews = {}

    def client(self, target: str) -> FMC:
        device = self.state.device(target, "fmc")
        # Credential or inventory changes take effect without reinstalling the plugin.
        if target in self.clients and self.clients[target].device != device:
            self.clients.pop(target).close()
        if target not in self.clients:
            self.clients[target] = self.client_factory(device, self.secrets, self.redactor)
        return self.clients[target]

    def close(self):
        for client in self.clients.values():
            client.close()

    def health(self) -> dict:
        return {"version": "0.3.1", "devices_enrolled": len(self.state.aliases()),
                "schema": self.catalog.provenance, "network_access_tested": False,
                "native_store": "macOS Keychain or Windows Credential Manager (opened only when needed)",
                "runtime_writes": "deployment tool only; special operational APIs disabled",
                "private_config_directory": str(self.state.config), "private_data_directory": str(self.state.data)}

    def connect(self, target: str) -> dict:
        client = self.client(target)
        version = client.version(refresh=True)
        return {"target": target, "domain": client.domain_name, "domain_uuid": client.domain,
                "server_version": version, "compatibility": client.compatibility()}

    def _call(self, target: str, op_id: str, path: dict | None = None, query: dict | None = None,
              headers: dict | None = None, body=None) -> dict:
        client = self.client(target)
        client.authenticate()
        request = self.catalog.prepare(op_id, path or {}, query or {}, headers or {}, body, client.domain)
        result = client.request(**request)
        result["schema_warnings"] = self.catalog.validate_response(op_id, result["status"], result["body"])
        return result

    def _read(self, target: str, op_id: str, path=None, query=None, all_pages=False, headers=None) -> dict:
        op = self.catalog.get(op_id)
        if op["effect"] != "read":
            raise AssistantError("read_operation_required", "Choose a GET operation for reads and verification.")
        query = dict(query or {})
        headers = self.secrets.resolve(headers or {})
        parameter_names = {self.catalog.resolve(p)["name"] for p in op["parameters"]}
        paginated = {"offset", "limit"}.issubset(parameter_names)
        if "expanded" in parameter_names:
            query.setdefault("expanded", True)
        if all_pages and paginated:
            query.setdefault("limit", 100)
            query.setdefault("offset", 0)
            if not 1 <= query["limit"] <= 1000:
                raise AssistantError("invalid_page_size", "Use a page size from 1 to 1000.")
        result = self._call(target, op_id, path, query, headers)
        result["complete"] = True
        if not all_pages or not paginated:
            if isinstance(result["body"], dict) and isinstance(result["body"].get("items"), list):
                result["complete"] = not bool(result["body"].get("paging", {}).get("next"))
            return result
        items = []
        for page in range(50):
            payload = result["body"]
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise AssistantError("pagination_shape_invalid", "Expected a paginated JSON items response.")
            batch = payload["items"]
            items.extend(batch)
            paging = payload.get("paging", {})
            pages = paging.get("pages")
            exhausted = not batch or ("next" in paging and not paging["next"])
            if isinstance(pages, int) and pages >= 0:
                exhausted = exhausted or query["offset"] // query["limit"] + 1 >= pages
            elif "next" not in paging:
                exhausted = exhausted or len(batch) < query["limit"]
            if exhausted:
                break
            if page == 49 or len(items) >= 5000:
                result["complete"] = False
                break
            query["offset"] += len(batch)
            next_result = self._call(target, op_id, path, query, headers)
            next_result["complete"] = True
            result = next_result
        result["body"] = {**result["body"], "items": items,
                          "paging": {"returned": len(items), "complete": result["complete"]}}
        return result

    def read(self, target: str, op_id: str, path=None, query=None, all_pages=True, headers=None) -> dict:
        result = self._read(target, op_id, path, query, all_pages, headers)
        return self.record(target, op_id, result)

    def record(self, target: str, op_id: str, result: dict, **extra) -> dict:
        client = self.clients.get(target)
        return self.evidence.save({"ok": True, "target": target, "operation_id": op_id,
                                   "domain": client.domain_name if client else None,
                                   "domain_uuid": client.domain if client else None,
                                   "compatibility": client.compatibility() if client else None,
                                   "deployment_performed": False, "runtime_verified": False,
                                   "result": result, **extra})

    def execute(self, target: str, op_id: str, authorization_request: str, path=None, query=None,
                headers=None, body=None) -> dict:
        op = self.catalog.get(op_id)
        if op["effect"] != "configuration":
            raise AssistantError("operation_guard", "This executor accepts ordinary configuration operations only. Use reads or the separate explicit-deployment tool.",
                                 effect=op["effect"])
        if not authorization_request.strip():
            raise AssistantError("request_scope_required", "Supply the current user's configuration request for the audit record.")
        # Authorization text is model-provided context, not an independently verified signature.
        # Host approvals and device RBAC remain independent controls.
        with self.state.target_lock(target):
            client = self.client(target)
            client.require_write_compatibility()
            resolved_query = self.secrets.resolve(query or {})
            resolved_headers = self.secrets.resolve(headers or {})
            resolved_body = self.secrets.resolve(body)
            self.catalog.prepare(op_id, path or {}, resolved_query, resolved_headers, resolved_body, client.domain)
            before = None
            peer = next((o for o in self.catalog.operations.values()
                         if o["method"] == "get" and o["path"] == op["path"]), None)
            if op["method"] in {"put", "delete"} and peer and "{objectId}" in op["path"]:
                before = self._read(target, peer["id"], path, all_pages=False)["body"]
            try:
                result = self._call(target, op_id, path, resolved_query, resolved_headers, resolved_body)
            except AssistantError as error:
                receipt = self.evidence.save({"ok": False, "target": target, "operation_id": op_id,
                                              "authorization_request": authorization_request,
                                              "before": before, "deployment_performed": False,
                                              "error": error.result()["error"]})
                error.details["run_id"] = receipt["run_id"]
                raise
            verification = {"status": "pending_async_completion" if result["asynchronous"] else "not_available"}
            if not result["asynchronous"]:
                verification = self._readback(target, op, path or {}, resolved_body, result, peer)
            return self.record(target, op_id, result, authorization_request=authorization_request,
                               before=before, verification=verification)

    def _readback(self, target, op, path, body, result, peer):
        try:
            if op["method"] == "delete" and peer and "{objectId}" in op["path"]:
                try:
                    self._read(target, peer["id"], path, all_pages=False)
                except AssistantError as error:
                    if error.details.get("status") == 404:
                        return {"status": "verified_absent"}
                    raise
                return {"status": "mismatch", "reason": "resource_still_present"}
            requested = body if isinstance(body, list) else [body]
            payload = result["body"]
            returned = payload.get("items", [payload]) if isinstance(payload, dict) else []
            candidate = peer if "{objectId}" in op["path"] else next(
                (o for o in self.catalog.operations.values() if o["method"] == "get" and
                 o["path"] == op["path"] + "/{objectId}"), None)
            if not candidate or len(requested) != len(returned):
                return {"status": "requires_explicit_verification"}
            checks = []
            for expected, created in zip(requested, returned):
                identifier = path.get("objectId") or (created.get("id") if isinstance(created, dict) else None)
                if not identifier or not isinstance(expected, dict):
                    return {"status": "requires_explicit_verification"}
                actual = self._read(target, candidate["id"], {**path, "objectId": identifier}, all_pages=False)
                checks.append({"object_id": identifier, "mismatches": compare(expected, actual["body"]),
                               "observed": actual["body"], "schema_warnings": actual["schema_warnings"]})
            return {"status": "mismatch" if any(x["mismatches"] for x in checks) else "verified_in_fmc",
                    "checks": checks}
        except AssistantError as error:
            return {"status": "verification_failed", "error": error.result()["error"],
                    "note": "Write was accepted. Do not repeat it; reconcile with a read."}

    def verify(self, target: str, op_id: str, expected, path=None, query=None, exact=False, headers=None) -> dict:
        # Prevent credential values from being copied into comparison requests or artifacts.
        if not exact and expected in ({}, []):
            raise AssistantError("expectations_required", "Specify meaningful expected fields, or use exact mode to assert an empty result.")
        expected = self.secrets.resolve(expected)
        result = self._read(target, op_id, path, query, all_pages=True, headers=headers)
        if not result["complete"]:
            raise AssistantError("verification_incomplete", "Pagination limits were reached; narrow the query before asserting a match.")
        mismatches = compare(expected, result["body"], exact)
        return self.record(target, op_id, result, verification={
            "status": "mismatch" if mismatches else "verified_in_fmc", "mismatches": mismatches,
            "mode": "exact" if exact else "object_subset_with_ordered_lists"})

    @staticmethod
    def _digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _deployment_snapshot(self, target: str, device_ids: list[str]) -> dict:
        self.client(target).require_write_compatibility()
        available = self._read(target, "getDeployableDevice", all_pages=True)
        if not available["complete"]:
            raise AssistantError("deployment_preview_incomplete", "Deployable-device enumeration is incomplete.")
        devices = {d["id"]: d for d in available["body"].get("items", []) if "id" in d}
        selected = []
        for identifier in device_ids:
            if identifier not in devices:
                raise AssistantError("device_not_deployable", "Requested device is absent from the deployable-device response.", device_id=identifier)
            item = devices[identifier]
            if item.get("canBeDeployed") is not True or item.get("isDeploying"):
                raise AssistantError("device_not_ready", "The device is not ready for deployment.", device_id=identifier)
            pending = self._read(target, "getPendingChanges", {"containerUUID": identifier}, all_pages=True)
            if not pending["complete"]:
                raise AssistantError("deployment_preview_incomplete", "Pending-change enumeration is incomplete.")
            selected.append({"id": identifier, "name": item.get("name"), "version": item.get("version"),
                             "traffic_interruption": item.get("trafficInterruption"),
                             "pending_changes": pending["body"]})
        versions = {d["version"] for d in selected}
        if len(versions) != 1 or None in versions:
            raise AssistantError("deployment_version_ambiguous", "Preview devices individually; a common deployment version was not returned.")
        return {"devices": selected, "version": next(iter(versions)), "scope": "all_pending_on_selected_devices"}

    def preview_deployment(self, target: str, device_ids: list[str]) -> dict:
        if not device_ids or len(set(device_ids)) != len(device_ids) or len(device_ids) > 25:
            raise AssistantError("invalid_deployment_targets", "Supply 1–25 distinct FMC device UUIDs.")
        with self.state.target_lock(target):
            snapshot = self._deployment_snapshot(target, device_ids)
            preview_id = str(uuid.uuid4())
            self.previews = {k: v for k, v in self.previews.items() if v["expires"] > time.monotonic()}
            self.previews[preview_id] = {"target": target, "device_ids": device_ids, "snapshot": snapshot,
                                         "digest": self._digest(snapshot), "expires": time.monotonic() + 300}
            return self.record(target, "deployment_preview", {"body": snapshot}, preview_id=preview_id,
                               expires_in_seconds=300,
                               note="This preview does not authorize deployment. It includes all pending changes, including other users' changes.")

    def deploy(self, target: str, preview_id: str, authorization_request: str, scope: str) -> dict:
        if not authorization_request.strip() or scope != "all_pending_on_selected_devices":
            raise AssistantError("explicit_deployment_scope_required", "Use only after the user explicitly requests deployment and authorizes all pending changes on these selected devices.")
        preview = self.previews.pop(preview_id, None)
        if not preview or preview["target"] != target or preview["expires"] <= time.monotonic():
            raise AssistantError("deployment_preview_expired", "Create a fresh deployment preview for this target.")
        with self.state.target_lock(target):
            snapshot = self._deployment_snapshot(target, preview["device_ids"])
            if self._digest(snapshot) != preview["digest"]:
                raise AssistantError("deployment_changed", "Deployment state changed since preview; review a fresh preview.")
            body = {"type": "DeploymentRequest", "deviceList": preview["device_ids"],
                    "version": snapshot["version"], "forceDeploy": False, "ignoreWarning": False}
            try:
                result = self._call(target, "createDeploymentRequest", body=body)
            except AssistantError as error:
                receipt = self.evidence.save({"ok": False, "target": target, "operation_id": "createDeploymentRequest",
                                              "authorization_request": authorization_request, "preview_id": preview_id,
                                              "deployment_outcome": "unknown_or_rejected", "error": error.result()["error"]})
                error.details["run_id"] = receipt["run_id"]
                raise
            return self.record(target, "createDeploymentRequest", result,
                               authorization_request=authorization_request, deployment_performed=True,
                               deployment_state="requested; completion and runtime behavior not yet verified",
                               preview_id=preview_id, scope=scope)
