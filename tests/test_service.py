import json
import time

import httpx
import pytest

from secure_firewall_assistant.errors import AssistantError

NETWORK = {"name": "branch", "type": "Network", "value": "192.0.2.0/24"}


def test_create_update_delete_readback_and_no_implicit_deployment(assistant, lab):
    created = assistant.execute("lab-fmc-1", "createMultipleNetworkObject", "Create branch", body=NETWORK)
    assert created["verification"]["status"] == "verified_in_fmc"
    assert created["deployment_performed"] is False
    updated = assistant.execute("lab-fmc-1", "updateNetworkObject", "Update branch",
                                path={"objectId": "net-1"}, body={**NETWORK, "id": "net-1", "value": "198.51.100.0/24"})
    assert updated["before"]["value"] == "192.0.2.0/24"
    assert updated["verification"]["status"] == "verified_in_fmc"
    deleted = assistant.execute("lab-fmc-1", "deleteNetworkObject", "Delete branch", path={"objectId": "net-1"})
    assert deleted["verification"]["status"] == "verified_absent"
    assert not any("deploymentrequests" in r.url.path for r in lab.calls)


@pytest.mark.parametrize("operation", ["createDeploymentRequest", "createRollbackRequest", "createBulkCommand", "createDomainManagement"])
def test_general_executor_cannot_reach_deployment_or_special_operations(assistant, lab, operation):
    with pytest.raises(AssistantError) as error:
        assistant.execute("lab-fmc-1", operation, "ordinary configuration", body={})
    assert error.value.code == "operation_guard"
    assert not lab.calls


def test_missing_scope_or_bad_payload_does_not_write(assistant, lab):
    with pytest.raises(AssistantError):
        assistant.execute("lab-fmc-1", "createMultipleNetworkObject", "", body=NETWORK)
    assert not lab.calls
    with pytest.raises(AssistantError):
        assistant.execute("lab-fmc-1", "createMultipleNetworkObject", "Create branch", body={"type": "Network"})
    assert not any(r.url.path.endswith("networks") and r.method == "POST" for r in lab.calls)


def test_readback_mismatch_is_not_success(assistant, lab):
    def lie(request):
        if request.method == "GET" and request.url.path.endswith("net-1"):
            return httpx.Response(200, json={**NETWORK, "id": "net-1", "value": "198.51.100.0/24"})
    lab.override = lie
    result = assistant.execute("lab-fmc-1", "createMultipleNetworkObject", "Create branch", body=NETWORK)
    assert result["verification"]["status"] == "mismatch"


def test_pagination_never_follows_remote_links(assistant, lab):
    def pages(request):
        if request.url.path.endswith("networks"):
            offset = int(request.url.params.get("offset", 0))
            return httpx.Response(200, json={"items": [{**NETWORK, "id": f"net-{offset}"}],
                                            "paging": {"next": ["https://outside.invalid/steal"] if offset < 2 else []}})
    lab.override = pages
    result = assistant.read("lab-fmc-1", "getAllNetworkObject", query={"limit": 1})
    assert len(result["result"]["body"]["items"]) == 3
    assert result["result"]["complete"] is True
    assert all(r.url.host == "fmc.example.invalid" for r in lab.calls)


def test_incomplete_pagination_cannot_pass_verification(assistant, lab):
    def endless(request):
        if request.url.path.endswith("networks"):
            return httpx.Response(200, json={"items": [{**NETWORK, "id": str(request.url.params.get("offset", 0))}],
                                            "paging": {"next": ["next"]}})
    lab.override = endless
    with pytest.raises(AssistantError) as error:
        assistant.verify("lab-fmc-1", "getAllNetworkObject", {"items": []}, query={"limit": 1})
    assert error.value.code == "verification_incomplete"


def test_expected_rules_compare_order_and_boolean_types(assistant, lab):
    lab.objects = {"net-1": {**NETWORK, "id": "net-1"}, "net-2": {**NETWORK, "name": "other", "id": "net-2"}}
    result = assistant.verify("lab-fmc-1", "getAllNetworkObject", {"items": [{"name": "other"}, {"name": "branch"}]})
    assert result["verification"]["status"] == "mismatch"
    result = assistant.verify("lab-fmc-1", "getAllNetworkObject", {"items": [{"name": "branch"}, {"name": "other"}]})
    assert result["verification"]["status"] == "verified_in_fmc"


def test_deployment_preview_and_single_use_scope(assistant, lab):
    preview = assistant.preview_deployment("lab-fmc-1", ["ftd-1"])
    assert preview["deployment_performed"] is False
    assert not any(r.url.path.endswith("deploymentrequests") for r in lab.calls)
    result = assistant.deploy("lab-fmc-1", preview["preview_id"],
                              "Deploy all pending changes on lab-ftd-1", "all_pending_on_selected_devices")
    assert result["deployment_performed"] is True
    assert result["result"]["asynchronous"] is True
    payload = json.loads(next(r.content for r in lab.calls if r.url.path.endswith("deploymentrequests")))
    assert payload["forceDeploy"] is False and payload["ignoreWarning"] is False
    assert payload["version"] == "12345"
    with pytest.raises(AssistantError) as error:
        assistant.deploy("lab-fmc-1", preview["preview_id"], "Deploy all", "all_pending_on_selected_devices")
    assert error.value.code == "deployment_preview_expired"


@pytest.mark.parametrize("change", ["pending", "expired", "target", "scope"])
def test_deployment_refuses_stale_or_unscoped_preview(assistant, lab, change):
    preview = assistant.preview_deployment("lab-fmc-1", ["ftd-1"])
    target, scope = "lab-fmc-1", "all_pending_on_selected_devices"
    if change == "pending":
        lab.pending.append({"entityUUID": "other", "action": "ADD"})
    elif change == "expired":
        assistant.previews[preview["preview_id"]]["expires"] = time.monotonic() - 1
    elif change == "target":
        target = "other-fmc"
    else:
        scope = "only-my-changes"
    with pytest.raises(AssistantError):
        assistant.deploy(target, preview["preview_id"], "Deploy all", scope)
    assert not any(r.url.path.endswith("deploymentrequests") for r in lab.calls)


def test_bulk_readback_and_failure_evidence_pagination(assistant):
    result = assistant.execute("lab-fmc-1", "createMultipleNetworkObject", "Create two networks",
                                query={"bulk": True}, body=[NETWORK, {**NETWORK, "name": "other"}])
    assert result["verification"]["status"] == "verified_in_fmc"
    read = assistant.read("lab-fmc-1", "getAllNetworkObject")
    page = assistant.evidence.read(read["run_id"], limit=1)
    assert len(page["result"]["body"]["items"]) == 1
    assert page["evidence_page"]["next_offset"] == 1


def test_unknown_alias_and_cross_domain_are_rejected(assistant, lab):
    with pytest.raises(AssistantError) as error:
        assistant.connect("not-enrolled")
    assert error.value.code == "unknown_target"
    assert not lab.calls
    with pytest.raises(AssistantError) as error:
        assistant.read("lab-fmc-1", "getAllNetworkObject", path={"domainUUID": "other"})
    assert error.value.code == "domain_mismatch"
