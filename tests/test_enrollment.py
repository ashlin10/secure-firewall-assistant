import threading
import time

import httpx
import pytest

from secure_firewall_assistant.enrollment import EnrollmentServer, job_path, status
from secure_firewall_assistant.errors import AssistantError
from secure_firewall_assistant.state import Device, State, atomic_json


@pytest.fixture
def form(tmp_path):
    state = State(tmp_path / "config", tmp_path / "data")
    class Store:
        def __init__(self):
            self.values = {}

        def set(self, reference, value):
            self.values[reference] = value
    store = Store()
    device = Device("fixture", "fmc", "https://fmc.example.invalid:12202", "tester", "fixture-auth")
    server = EnrollmentServer(device, state, store)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    yield server, state, store
    server.shutdown()
    server.server_close()
    worker.join()


def submit(server, **updates):
    fields = {"csrf": server.nonce, "password": "synthetic-form-value", "repeat": "synthetic-form-value",
              "domain": "Global", "ca": ""}
    fields.update(updates)
    return fields


def test_local_form_saves_once_without_disclosing_secret(form, capsys):
    server, state, store = form
    url = server.origin + server.form_path
    page = httpx.get(url)
    assert page.status_code == 200 and 'type="password"' in page.text
    assert page.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    result = httpx.post(url, data=submit(server), headers={"Origin": server.origin})
    assert result.status_code == 200
    assert "synthetic-form-value" not in result.text
    assert store.values == {"fixture-auth": "synthetic-form-value"}
    assert "synthetic-form-value" not in state.inventory_path.read_text()
    assert state.device("fixture").domain == "Global"
    assert httpx.get(url).status_code == 404
    assert httpx.post(url, data=submit(server), headers={"Origin": server.origin}).status_code == 403
    assert "synthetic-form-value" not in str(capsys.readouterr())


@pytest.mark.parametrize("headers,changes", [
    ({"Origin": "https://evil.example"}, {}),
    ({}, {}),
    ({"Host": "evil.example"}, {}),
    ({}, {"csrf": "wrong"}),
])
def test_forged_requests_never_store_credentials(form, headers, changes):
    server, state, store = form
    actual = {"Origin": server.origin, **headers}
    if not headers and not changes:
        actual = {}
    response = httpx.post(server.origin + server.form_path, data=submit(server, **changes), headers=actual)
    assert response.status_code == 403
    assert store.values == {} and state.aliases() == []


def test_password_mismatch_and_missing_ca_leave_enrollment_empty(form):
    server, state, store = form
    for changes in ({"repeat": "different"}, {"ca": "/nonexistent/ca.pem"}):
        result = httpx.post(server.origin + server.form_path, data=submit(server, **changes),
                            headers={"Origin": server.origin})
        assert result.status_code == 400
        assert "synthetic-form-value" not in result.text
        assert store.values == {} and state.aliases() == []


def test_expiry_and_existing_alias_do_not_overwrite(form):
    server, state, store = form
    state.save_device(server.device)
    result = httpx.post(server.origin + server.form_path, data=submit(server), headers={"Origin": server.origin})
    assert result.status_code == 409 and store.values == {}
    server.expires = time.time() - 1
    assert httpx.get(server.origin + server.form_path).status_code == 404


def test_status_has_only_safe_fields_and_blocks_path_traversal(form):
    server, state, store = form
    identifier = "a" * 32
    atomic_json(job_path(state, identifier), {"device": {"alias": "fixture"}, "status": "waiting",
                                            "expires": time.time() - 1, "url": "not-returned"})
    assert status(state, identifier) == {"enrollment_id": identifier, "alias": "fixture", "status": "expired"}
    with pytest.raises(AssistantError):
        job_path(state, "../../inventory")
