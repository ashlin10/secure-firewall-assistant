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
