import json
from dataclasses import replace

import httpx
import pytest

from secure_firewall_assistant.errors import AssistantError


def test_auth_reuse_and_refresh_limits(assistant, lab):
    client = assistant.client("lab-fmc-1")
    client.version()
    client.request("get", "/api/fmc_platform/v1/info/serverversion")
    assert lab.token_count == 1
    for _ in range(4):
        client.expires = 0
        client.authenticate()
    assert sum(r.url.path.endswith("refreshtoken") for r in lab.calls) == 3
    assert sum(r.url.path.endswith("generatetoken") for r in lab.calls) == 2
    cleaned = assistant.redactor.clean({"echo": client.access, "headers": {"X-auth-access-token": client.access},
                                        "echo_login": assistant.secrets.get("lab-fmc-1-auth")})
    assert "SYNTHETIC" not in json.dumps(cleaned)


def test_reads_can_reauthenticate_but_writes_are_not_replayed(assistant, lab, monkeypatch):
    monkeypatch.setattr("secure_firewall_assistant.fmc.time.sleep", lambda _: None)
    state = {"count": 0}

    def reject(request):
        if request.url.path.endswith("object/networks"):
            state["count"] += 1
            return httpx.Response(401, json={"error": {"category": "FRAMEWORK"}})
    lab.override = reject
    with pytest.raises(AssistantError):
        assistant.read("lab-fmc-1", "getAllNetworkObject")
    assert state["count"] == 2
    state["count"] = 0
    with pytest.raises(AssistantError):
        assistant.execute("lab-fmc-1", "createMultipleNetworkObject", "Create the named object",
                          body={"name": "branch", "type": "Network", "value": "192.0.2.0/24"})
    assert state["count"] == 1


def test_read_throttling_is_bounded(assistant, lab, monkeypatch):
    monkeypatch.setattr("secure_firewall_assistant.fmc.time.sleep", lambda _: None)
    count = []

    def limited(request):
        count.append(request.url.path)
        return httpx.Response(429, headers={"Retry-After": "999"}, json={"error": {}})
    lab.override = limited
    with pytest.raises(AssistantError) as error:
        assistant.read("lab-fmc-1", "getAllNetworkObject")
    assert error.value.details["status"] == 429
    assert len(count) == 3


def test_redirects_and_html_never_trigger_followup(assistant, lab):
    lab.override = lambda r: httpx.Response(302, headers={"Location": "https://outside.invalid"})
    with pytest.raises(AssistantError) as error:
        assistant.read("lab-fmc-1", "getAllNetworkObject")
    assert error.value.code == "redirect_rejected"
    assert all(r.url.host == "fmc.example.invalid" for r in lab.calls)
    lab.override = lambda r: httpx.Response(200, text="<html>UI login</html>")
    with pytest.raises(AssistantError) as error:
        assistant.read("lab-fmc-1", "getAllNetworkObject")
    assert error.value.code == "unsupported_response"


def test_unknown_write_outcome_is_recorded_without_retry(assistant, lab):
    def fail(request):
        if request.method == "POST":
            raise httpx.ReadTimeout("SYNTHETIC-LOGIN-SENTINEL")
    lab.override = fail
    with pytest.raises(AssistantError) as error:
        assistant.execute("lab-fmc-1", "createMultipleNetworkObject", "Create branch",
                          body={"name": "branch", "type": "Network", "value": "192.0.2.0/24"})
    assert error.value.details["outcome"] == "unknown"
    assert error.value.details["retry_write"] is False
    assert len([r for r in lab.calls if r.method == "POST" and r.url.path.endswith("networks")]) == 1
    assert "SYNTHETIC" not in json.dumps(error.value.result())
    assert assistant.evidence.read(error.value.details["run_id"])["ok"] is False


def test_version_constraint_blocks_writes(assistant, state, lab):
    state.save_device(replace(state.device("lab-fmc-1"), expected_version_prefix="99."))
    with pytest.raises(AssistantError) as error:
        assistant.execute("lab-fmc-1", "createMultipleNetworkObject", "Create branch",
                          body={"name": "branch", "type": "Network", "value": "192.0.2.0/24"})
    assert error.value.code == "version_mismatch"
    assert not any(r.url.path.endswith("networks") for r in lab.calls)


def test_ambiguous_domain_cannot_be_bypassed_by_cached_token(assistant, state, lab):
    state.save_device(replace(state.device("lab-fmc-1"), domain=None))
    client = assistant.client("lab-fmc-1")
    original = lab.handle

    def handler(request):
        if request.url.path.endswith("generatetoken"):
            return httpx.Response(204, headers={"X-auth-access-token": "SYNTHETIC-ACCESS",
                                               "DOMAINS": json.dumps([{"uuid": "a", "name": "A"}, {"uuid": "b", "name": "B"}])})
        return original(request)
    client.http.close()
    client.http = httpx.Client(base_url=state.device("lab-fmc-1").address, transport=httpx.MockTransport(handler))
    for _ in range(2):
        with pytest.raises(AssistantError) as error:
            client.authenticate()
        assert error.value.code == "domain_selection_required"
    assert client.domain is None


def test_real_self_signed_tls_default_and_strict_modes(tmp_path):
    import shutil
    import ssl
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from secure_firewall_assistant.fmc import FMC
    from secure_firewall_assistant.state import Device

    if not shutil.which('openssl'):
        pytest.skip('OpenSSL needed for real TLS test')
    key, cert = tmp_path / 'key.pem', tmp_path / 'cert.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost'],
                   check=True, capture_output=True)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{}')

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    device = Device(alias='tls-lab', kind='fmc', address=f'https://127.0.0.1:{server.server_port}',
                    username='fixture', credential_ref='fixture-auth')
    try:
        # Real TLS: default accepts both the self-signed issuer and hostname mismatch.
        client = FMC(device, None, None)
        try:
            assert client.http.get('/').status_code == 200
        finally:
            client.close()
        # Strict mode rejects the untrusted issuer; a CA bundle still checks hostnames.
        for strict in (replace(device, verify_ssl=True), replace(device, ca_bundle=str(cert))):
            client = FMC(strict, None, None)
            try:
                with pytest.raises(httpx.ConnectError, match='CERTIFICATE_VERIFY_FAILED'):
                    client.http.get('/')
            finally:
                client.close()
        # A trusted certificate with its matching hostname works with a CA bundle.
        client = FMC(replace(device, address=f'https://localhost:{server.server_port}', ca_bundle=str(cert)), None, None)
        try:
            assert client.http.get('/').status_code == 200
        finally:
            client.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_invalid_tls_settings_fail_before_connecting(tmp_path):
    from secure_firewall_assistant.fmc import FMC
    from secure_firewall_assistant.state import Device

    device = Device(alias='tls-lab', kind='fmc', address='https://fmc.example.invalid',
                    username='fixture', credential_ref='fixture-auth')
    with pytest.raises(AssistantError, match='verify_ssl'):
        replace(device, verify_ssl='false')
    with pytest.raises(AssistantError) as error:
        FMC(replace(device, ca_bundle=str(tmp_path / 'missing.pem')), None, None)
    assert error.value.code == 'ca_bundle_invalid'
