"""Embedded MCP App with a direct, short-lived loopback credential channel.

Passwords are never MCP arguments, results, widget state, or bridge messages.
The UI must run in the documented ChatGPT sandbox origin; other origins fail closed.
"""
import json
import secrets
import threading
import time
import uuid
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from mcp.types import CallToolResult, TextContent

from .errors import AssistantError
from .state import Device

SANDBOX_ORIGIN = "https://web-sandbox.oaiusercontent.com"
MIME = "text/html;profile=mcp-app"


class EnrollmentUI:
    def __init__(self, state, store):
        self.state, self.store = state, store
        self.sessions = {}
        self.lock = threading.RLock()
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.http.daemon_threads = True
        self.http.owner = self
        self.http.handle_error = lambda *_: None
        self.origin = f"http://127.0.0.1:{self.http.server_port}"
        # Each MCP process gets its own resource/cache key and exact CSP origin.
        self.uri = f"ui://secure-firewall/enrollment/v3/{uuid.uuid4().hex}.html"
        self.worker = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.worker.start()

    def close(self):
        self.http.shutdown()
        self.http.server_close()

    @property
    def resource_meta(self):
        return {"ui": {"prefersBorder": True, "csp": {"connectDomains": [self.origin], "resourceDomains": []}},
                "openai/widgetDescription": "Private device enrollment form. The user enters credentials here; never inspect or automate its password inputs.",
                "openai/widgetCSP": {"connect_domains": [self.origin], "resource_domains": []}}

    def start(self, kind, alias, address, username, domain=None):
        device = Device(kind=kind, alias=alias, address=address.rstrip("/"), username=username,
                        credential_ref=alias + "-auth", domain=domain)
        if alias in self.state.inventory()["devices"]:
            raise AssistantError("alias_exists", "This alias is already enrolled; no credential was changed.")
        identifier, authorization = uuid.uuid4().hex, secrets.token_urlsafe(32)
        with self.lock:
            self.sessions = {key: value for key, value in self.sessions.items() if value["expires"] > time.time()}
            if len(self.sessions) >= 16:
                raise AssistantError("enrollment_limit", "Complete an existing enrollment or wait for it to expire.")
            self.sessions[identifier] = {"device": device, "authorization": authorization,
                                         "expires": time.time() + 600, "status": "waiting"}
        public = {"enrollment_id": identifier, "alias": alias, "status": "waiting_for_private_form",
                  "expires_in_seconds": 600,
                  "next_step": "The user must fill the embedded enrollment card. Never open a browser or ask for a password in chat. If the card is absent, report that MCP Apps UI must be enabled/refreshed; do not fall back automatically."}
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(public))],
                              structured_content=public,
                              _meta={"enrollment": {"endpoint": self.origin + "/enroll/" + identifier,
                                                    "authorization": authorization, "alias": alias,
                                                    "address": device.address, "username": username,
                                                    "domain": domain or "", "expires": self.sessions[identifier]["expires"]}})

    def status(self, identifier):
        with self.lock:
            job = self.sessions.get(identifier)
            if job is None:
                raise AssistantError("unknown_enrollment", "This form belongs to another or restarted helper. Start a fresh form.")
            status = job["status"]
            if status == "waiting" and job["expires"] <= time.time():
                status = "expired"
            return {"enrollment_id": identifier, "alias": job["device"].alias, "status": status}

    def html(self):
        return Path(__file__).with_name("enrollment_card.html").read_text(encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass

    def reply(self, code, value):
        body = json.dumps(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Vary", "Origin")
        if self.headers.get("Origin") == SANDBOX_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", SANDBOX_ORIGIN)
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-SFA-Enrollment")
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()
        self.wfile.write(body)

    def job(self):
        owner = self.server.owner
        if (self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}" or
                self.headers.get("Origin") != SANDBOX_ORIGIN or
                not self.path.startswith("/enroll/")):
            return None
        identifier = self.path.removeprefix("/enroll/")
        with owner.lock:
            job = owner.sessions.get(identifier)
            if job and job["status"] == "waiting" and job["expires"] > time.time():
                return job
        return None

    def do_OPTIONS(self):
        if (not self.job() or self.headers.get("Access-Control-Request-Method") != "POST" or
                set(h.strip().lower() for h in self.headers.get("Access-Control-Request-Headers", "").split(",")) -
                {"content-type", "x-sfa-enrollment"}):
            return self.reply(403, {"ok": False})
        return self.reply(200, {"ok": True})

    def do_GET(self):
        # There is deliberately no browser page and no endpoint reading credentials.
        return self.reply(404, {"ok": False})

    def do_POST(self):
        job = self.job()
        if (job is None or not secrets.compare_digest(self.headers.get("X-SFA-Enrollment", ""), job["authorization"]) or
                self.headers.get("Content-Type", "").split(";")[0] != "application/json" or
                self.headers.get("Transfer-Encoding")):
            return self.reply(403, {"ok": False, "message": "Enrollment unavailable or request rejected."})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 32768:
                return self.reply(413, {"ok": False})
            fields = json.loads(self.rfile.read(size))
            if (not isinstance(fields, dict) or set(fields) != {"password", "repeat", "domain", "ca"} or
                    any(not isinstance(v, str) for v in fields.values())):
                return self.reply(400, {"ok": False, "message": "Invalid form fields."})
            if not fields["password"] or fields["password"] != fields["repeat"]:
                return self.reply(400, {"ok": False, "message": "Passwords must be nonempty and match."})
            ca = fields["ca"].strip()
            if ca and not Path(ca).expanduser().is_file():
                return self.reply(400, {"ok": False, "message": "The CA file was not found on this computer."})
            device = replace(job["device"], domain=fields["domain"].strip() or None,
                             ca_bundle=str(Path(ca).expanduser().resolve()) if ca else None)
            owner = self.server.owner
            with owner.lock, owner.state.target_lock(device.alias):
                if job["status"] != "waiting" or job["expires"] <= time.time():
                    return self.reply(409, {"ok": False, "message": "Start a fresh enrollment form."})
                if device.alias in owner.state.inventory()["devices"]:
                    return self.reply(409, {"ok": False, "message": "This alias is already enrolled."})
                owner.store.set(device.credential_ref, fields["password"])
                owner.state.save_device(device)
                job["status"] = "enrolled"
                job["authorization"] = ""
            return self.reply(200, {"ok": True, "alias": device.alias, "status": "enrolled"})
        except (ValueError, UnicodeError):
            return self.reply(400, {"ok": False, "message": "Invalid form submission."})
        except Exception:
            return self.reply(500, {"ok": False, "message": "Could not save enrollment. Check local credential-store access and retry."})
