import json
import ssl
import threading
import time

import httpx

from .errors import AssistantError
from .security import Redactor, SecretStore
from .state import Device


class FMC:
    def __init__(self, device: Device, secrets: SecretStore, redactor: Redactor,
                 transport: httpx.BaseTransport | None = None):
        self.device, self.secrets, self.redactor = device, secrets, redactor
        try:
            verify = ssl.create_default_context(cafile=device.ca_bundle) if device.ca_bundle else device.verify_ssl
        except (OSError, ssl.SSLError):
            raise AssistantError("ca_bundle_invalid", "The enrolled certificate trust bundle cannot be loaded.") from None
        self.http = httpx.Client(base_url=device.address.rstrip("/"), verify=verify, timeout=30,
                                 follow_redirects=False, trust_env=False, transport=transport)
        self.access = None
        self.refresh = None
        self.expires = 0.0
        self.refreshes = 0
        self.domain = None
        self.domain_name = None
        self.server_version = None
        self.lock = threading.RLock()

    def close(self):
        self.http.close()

    def _send(self, method: str, path: str, **kwargs) -> httpx.Response:
        try:
            with self.http.stream(method, path, **kwargs) as response:
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > 8 * 1024 * 1024:
                        raise AssistantError("response_too_large", "Use a smaller page size for this operation.",
                                             outcome="unknown" if method.lower() not in {"get", "head"} else "read_failed")
                response._content = bytes(body)
                return response
        except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError):
            raise AssistantError("connection_failed", "HTTPS connection failed; check reachability, certificate trust, and device status.",
                                 outcome="unknown" if method.lower() not in {"get", "head"} else "read_failed",
                                 retry_write=False) from None

    def authenticate(self, force: bool = False):
        with self.lock:
            if not force and self.access and self.domain and time.monotonic() < self.expires:
                return
            if not force and self.access and self.domain and self.refresh and self.refreshes < 3:
                response = self._send("POST", "/api/fmc_platform/v1/auth/refreshtoken", headers={
                    "X-auth-access-token": self.access, "X-auth-refresh-token": self.refresh})
                if response.status_code in (200, 204) and response.headers.get("X-auth-access-token"):
                    self._tokens(response)
                    self.refreshes += 1
                    return
            password = self.secrets.get(self.device.credential_ref, protocol="https")
            response = self._send("POST", "/api/fmc_platform/v1/auth/generatetoken",
                                  auth=httpx.BasicAuth(self.device.username, password))
            if response.status_code not in (200, 204) or not response.headers.get("X-auth-access-token"):
                raise AssistantError("authentication_failed", "FMC authentication failed. Check the locally enrolled account and API access.", status=response.status_code)
            self._tokens(response)
            self.refreshes = 0
            try:
                domains = json.loads(response.headers.get("DOMAINS", "[]"))
                if not isinstance(domains, list):
                    raise ValueError
                preferred = self.device.domain
                if preferred:
                    matches = [d for d in domains if preferred in (d.get("uuid"), d.get("name"))]
                    fallback = response.headers.get("DOMAIN_UUID")
                    if not matches and preferred == fallback:
                        matches = [{"uuid": fallback, "name": preferred}]
                elif len(domains) == 1:
                    matches = domains
                elif not domains and response.headers.get("DOMAIN_UUID"):
                    matches = [{"uuid": response.headers["DOMAIN_UUID"], "name": "Global"}]
                else:
                    matches = []
                if len(matches) != 1:
                    raise AssistantError("domain_selection_required", "Enroll an explicit domain name or UUID for this FMC.",
                                         domains=[{"name": d.get("name"), "uuid": d.get("uuid")} for d in domains])
                self.domain, self.domain_name = matches[0]["uuid"], matches[0].get("name")
            except (ValueError, TypeError, KeyError):
                raise AssistantError("invalid_auth_response", "FMC returned invalid domain metadata.") from None

    def _tokens(self, response):
        self.access = response.headers["X-auth-access-token"]
        self.refresh = response.headers.get("X-auth-refresh-token", self.refresh)
        self.redactor.register(self.access)
        self.redactor.register(self.refresh)
        self.expires = time.monotonic() + 25 * 60

    def request(self, method: str, path: str, query: dict | None = None,
                headers: dict | None = None, body=None) -> dict:
        if not path.startswith("/api/") or ".." in path or "?" in path or "#" in path or "\\" in path:
            raise AssistantError("invalid_api_path", "Only a catalog-generated API path is accepted.")
        # HTTPX supports shared clients across threads. Authentication remains locked;
        # independent configuration creates may overlap within the batch worker bound.
        self.authenticate()
        for attempt in range(3):
            request_headers = {"Accept": "application/json", **(headers or {}), "X-auth-access-token": self.access}
            params = {k: str(v).lower() if isinstance(v, bool) else v for k, v in (query or {}).items()}
            response = self._send(method.upper(), path, params=params, headers=request_headers,
                                  **({"json": body} if body is not None else {}))
            # Retry only reads. Never replay a write after an uncertain network/server outcome.
            if response.status_code == 401 and method.lower() == "get" and attempt == 0:
                self.authenticate(force=True)
                continue
            if response.status_code in (429, 502, 503) and method.lower() == "get" and attempt < 2:
                try:
                    delay = min(2.0, max(0.1, float(response.headers.get("Retry-After", 0.25))))
                except ValueError:
                    delay = 0.25
                time.sleep(delay)
                continue
            break
        if 300 <= response.status_code < 400:
            raise AssistantError("redirect_rejected", "FMC redirected the request. Update the enrolled origin; redirects are not followed.", status=response.status_code)
        try:
            result_body = response.json() if response.content else None
        except ValueError:
            raise AssistantError("unsupported_response", "FMC returned a non-JSON response; this release supports JSON APIs only.", status=response.status_code) from None
        if not 200 <= response.status_code < 300:
            raise AssistantError("fmc_api_error", "FMC rejected the request.", status=response.status_code,
                                 api_error=self.redactor.clean(result_body),
                                 outcome="unknown" if method.lower() != "get" and response.status_code >= 500 else "rejected",
                                 retry_write=False)
        return {"status": response.status_code, "body": result_body,
                "request_id": response.headers.get("X-Request-ID"),
                "asynchronous": response.status_code == 202}

    def version(self, refresh: bool = False) -> str:
        if refresh or self.server_version is None:
            result = self.request("get", "/api/fmc_platform/v1/info/serverversion")
            try:
                self.server_version = result["body"]["items"][0]["serverVersion"]
            except (KeyError, TypeError, IndexError):
                raise AssistantError("server_version_missing", "FMC version could not be established.") from None
        return self.server_version

    def require_write_compatibility(self):
        version = self.version(refresh=True)
        prefix = self.device.expected_version_prefix
        if prefix and not version.startswith(prefix):
            raise AssistantError("version_mismatch", "FMC version differs from the enrolled version constraint. Writes are blocked.",
                                 actual_version=version, expected_prefix=prefix)

    def compatibility(self) -> dict:
        return {"server_version": self.server_version,
                "schema_device_version_verified": False,
                "note": "Schema selection is reported separately. Exact version selection and latest fallback do not prove device compatibility."}
