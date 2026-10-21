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
        existing_fields = self.state.inventory()["devices"].get(alias)
        if existing_fields:
            existing = Device(**existing_fields)
            if (existing.kind != device.kind or existing.address != device.address or
                    existing.username != device.username):
                raise AssistantError("alias_exists", "This alias already has different device details; no credential was changed.")
            device = replace(existing, domain=domain if domain is not None else existing.domain)
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
                                                    "address": device.address, "username": username, "kind": kind,
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
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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
        path = self.path.removeprefix("/enroll/")
        identifier = path.removesuffix("/probe") if path.endswith("/probe") else path
        with owner.lock:
            job = owner.sessions.get(identifier)
            if job and job["status"] == "waiting" and job["expires"] > time.time():
                return job
        return None

    def do_GET(self):
        # A password-free probe lets the user confirm iframe-to-loopback access
        # before entering a credential. The token is session-scoped and never
        # returned to the model or written to logs.
        job = self.job()
        if (job is None or not self.path.endswith("/probe") or
                not secrets.compare_digest(self.headers.get("X-SFA-Enrollment", ""), job["authorization"])):
            return self.reply(403, {"ok": False, "message": "Enrollment connection unavailable or request rejected."})
        return self.reply(200, {"ok": True})

    def do_OPTIONS(self):
        if (not self.job() or self.headers.get("Access-Control-Request-Method") not in {"GET", "POST"} or
                set(h.strip().lower() for h in self.headers.get("Access-Control-Request-Headers", "").split(",")) -
                {"content-type", "x-sfa-enrollment"}):
            return self.reply(403, {"ok": False})
        return self.reply(200, {"ok": True})

    def do_POST(self):
        # Consume bounded request bodies before rejecting authorization. Closing a
        # Windows socket with unread data can reset it and hide the JSON error.
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.reply(400, {"ok": False, "message": "Invalid form submission."})
        if not 0 < size <= 32768 or self.headers.get("Transfer-Encoding"):
            return self.reply(413, {"ok": False})
        raw = self.rfile.read(size)
        job = self.job()
        if (job is None or not secrets.compare_digest(self.headers.get("X-SFA-Enrollment", ""), job["authorization"]) or
                self.headers.get("Content-Type", "").split(";")[0] != "application/json" or
                self.headers.get("Transfer-Encoding")):
            return self.reply(403, {"ok": False, "message": "Enrollment unavailable or request rejected."})
        try:
            fields = json.loads(raw)
            if (not isinstance(fields, dict) or set(fields) != {"password", "repeat"} or
                    any(not isinstance(v, str) for v in fields.values())):
                return self.reply(400, {"ok": False, "message": "Invalid form fields."})
            if not fields["password"] or fields["password"] != fields["repeat"]:
                return self.reply(400, {"ok": False, "message": "Passwords must be nonempty and match."})
            device = job["device"]
            owner = self.server.owner
            with owner.lock:
                if job["status"] != "waiting" or job["expires"] <= time.time():
                    return self.reply(409, {"ok": False, "message": "Start a fresh enrollment form."})
                job["status"] = "saving"
            try:
                # Native-store prompts can block. Status reads must remain available.
                with owner.state.target_lock(device.alias):
                    existing_fields = owner.state.inventory()["devices"].get(device.alias)
                    if existing_fields and Device(**existing_fields) != device:
                        return self.reply(409, {"ok": False, "message": "This alias now has different device details."})
                    owner.store.set(device.credential_ref, fields["password"], device=device)
                    owner.state.save_device(device)
                with owner.lock:
                    job["status"] = "enrolled"
                    job["authorization"] = ""
            finally:
                with owner.lock:
                    if job["status"] == "saving":
                        job["status"] = "waiting"
            return self.reply(200, {"ok": True, "alias": device.alias, "status": "enrolled"})
        except (ValueError, UnicodeError):
            return self.reply(400, {"ok": False, "message": "Invalid form submission."})
        except Exception:
            return self.reply(500, {"ok": False, "message": "Could not save enrollment to local devices.yaml. Check the file and folder permissions, then retry."})
