"""Short-lived loopback enrollment; passwords never pass through MCP or logs."""
import html
import json
import os
import re
import secrets
import subprocess
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from .errors import AssistantError
from .security import Redactor, SecretStore
from .state import Device, State, atomic_json, private_dir


def job_path(state, identifier):
    if not re.fullmatch(r"[a-f0-9]{32}", identifier):
        raise AssistantError("invalid_enrollment", "Invalid enrollment identifier.")
    return private_dir(state.data / "enrollment") / (identifier + ".json")


def status(state, identifier):
    path = job_path(state, identifier)
    if not path.is_file():
        raise AssistantError("unknown_enrollment", "Enrollment was not found.")
    job = json.loads(path.read_text())
    result = {"enrollment_id": identifier, "alias": job["device"]["alias"], "status": job["status"]}
    if job["status"] in {"starting", "waiting"} and time.time() > job["expires"]:
        result["status"] = "expired"
    return result


def start(state, kind, alias, address, username, domain=None):
    device = Device(kind=kind, alias=alias, address=address.rstrip("/"), username=username,
                    credential_ref=alias + "-auth", domain=domain)
    if alias in state.inventory()["devices"]:
        raise AssistantError("alias_exists", "This alias is already enrolled; use the local utility to replace it.")
    identifier = uuid.uuid4().hex
    path = job_path(state, identifier)
    from dataclasses import asdict
    job = {"device": asdict(device), "status": "starting", "expires": time.time() + 600,
           "config": str(state.config), "data": str(state.data)}
    atomic_json(path, job)
    subprocess.Popen([sys.executable, "-m", __name__, str(path)], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=(os.name != "nt"),
                     creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
    for _ in range(60):
        job = json.loads(path.read_text())
        if job["status"] == "waiting":
            return {"enrollment_id": identifier, "alias": alias, "enrollment_url": job["url"],
                    "expires_in_seconds": max(0, int(job["expires"] - time.time())),
                    "next_step": "Open the local URL for the user. Hand off password entry; never inspect, fill, screenshot, or read the form after they start typing. Check enrollment_status afterward."}
        if job["status"] != "starting":
            break
        time.sleep(0.05)
    raise AssistantError("enrollment_start_failed", "The local enrollment window could not start. Retry or use the local management utility.")


class EnrollmentServer(HTTPServer):
    def __init__(self, device, state, store, expires=None):
        self.device, self.state, self.store = device, state, store
        self.expires = expires or time.time() + 600
        self.form_path = "/enroll/" + secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(32)
        self.completed = False
        super().__init__(("127.0.0.1", 0), EnrollmentHandler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.timeout = 0.5

    def handle_error(self, request, client_address):
        pass


class EnrollmentHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    # Suppress request lines, URLs, headers, submitted values, and exceptions.
    def log_message(self, *_):
        pass

    def reply(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

    def valid(self):
        return (self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}" and
                self.path == self.server.form_path and not self.server.completed and
                time.time() < self.server.expires)

    def page(self, message=""):
        d = self.server.device
        fields = "".join(f'<p><b>{label}</b><br>{html.escape(value)}</p>' for label, value in
                         [("Device", d.alias), ("Type", d.kind.upper()), ("Address", d.address), ("Username", d.username)])
        return f'''<!doctype html><html><meta charset="utf-8"><title>Enroll Secure Firewall device</title>
<style>body{{font:17px system-ui;max-width:560px;margin:40px auto;padding:24px;background:#f3f6fa;color:#152238}}main{{background:white;padding:32px;border-radius:16px}}input,button{{box-sizing:border-box;width:100%;padding:12px;margin:8px 0 18px;font:inherit}}button{{background:#154bba;color:white;border:0;border-radius:8px}}.message{{color:#9b2424}}small{{color:#48566a}}</style>
<main><h1>Enroll device</h1><p>Secure Firewall Assistant · local setup</p>{fields}
<p class="message">{html.escape(message)}</p>
<form method="post" action="{self.server.form_path}" autocomplete="off">
<input type="hidden" name="csrf" value="{self.server.nonce}">
<label>Password<input type="password" name="password" required autocomplete="new-password" maxlength="4096"></label>
<label>Repeat password<input type="password" name="repeat" required autocomplete="new-password" maxlength="4096"></label>
<label>FMC domain (optional)<input name="domain" value="{html.escape(d.domain or '', quote=True)}" maxlength="256" placeholder="Leave blank to discover"></label>
<label>CA certificate file (optional)<input name="ca" maxlength="2048" placeholder="Full path to a trusted PEM bundle"></label>
<button>Save enrollment</button></form>
<small>Runs on this computer only. Saves the password in Keychain or Windows Credential Manager. No password is returned to chat. Expires after 10 minutes. Certificate verification remains enabled.</small></main></html>'''

    def do_GET(self):
        if not self.valid():
            return self.reply(404, "Enrollment unavailable or expired.")
        return self.reply(200, self.page())

    def do_POST(self):
        if (not self.valid() or self.headers.get("Origin") != self.server.origin or
                self.headers.get("Content-Type", "").split(";")[0] != "application/x-www-form-urlencoded" or
                self.headers.get("Transfer-Encoding")):
            return self.reply(403, "Request rejected.")
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 32768:
                return self.reply(413, "Request rejected.")
            values = parse_qs(self.rfile.read(size).decode(), keep_blank_values=True, max_num_fields=6)
            if set(values) != {"csrf", "password", "repeat", "domain", "ca"} or any(len(v) != 1 for v in values.values()):
                return self.reply(400, "Request rejected.")
            if not secrets.compare_digest(values["csrf"][0], self.server.nonce):
                return self.reply(403, "Request rejected.")
            password = values["password"][0]
            if not password or password != values["repeat"][0]:
                return self.reply(400, self.page("Passwords must be nonempty and match. Please enter them again."))
            ca = values["ca"][0].strip()
            if ca and not Path(ca).expanduser().is_file():
                return self.reply(400, self.page("The CA file was not found on this computer."))
            from dataclasses import replace
            device = replace(self.server.device, domain=values["domain"][0].strip() or None,
                             ca_bundle=str(Path(ca).expanduser().resolve()) if ca else None)
            with self.server.state.target_lock(device.alias):
                if device.alias in self.server.state.inventory()["devices"]:
                    return self.reply(409, "This alias is already enrolled. Nothing was changed.")
                self.server.store.set(device.credential_ref, password)
                self.server.state.save_device(device)
            self.server.completed = True
            return self.reply(200, "<title>Enrollment saved</title><h1>Enrollment saved</h1><p>Your password is stored in the native credential store. Return to ChatGPT to check connectivity. You can close this window.</p>")
        except (ValueError, UnicodeError):
            return self.reply(400, "Request rejected.")
        except Exception:
            return self.reply(500, self.page("Enrollment could not finish. Check native credential-store access and local file permissions, then retry."))


def run(path):
    job = json.loads(path.read_text())
    state = State(config=Path(job["config"]), data=Path(job["data"]))
    # The process and its in-memory redactor exit after submission or timeout.
    store = SecretStore(Redactor())
    with EnrollmentServer(Device(**job["device"]), state, store, job["expires"]) as server:
        job.update(status="waiting", url=server.origin + server.form_path)
        atomic_json(path, job)
        while time.time() < server.expires and not server.completed:
            server.handle_request()
        job.pop("url", None)
        job["status"] = "enrolled" if server.completed else "expired"
        atomic_json(path, job)


if __name__ == "__main__":
    run(Path(sys.argv[1]))
