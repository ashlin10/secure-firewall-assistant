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


@pytest.mark.parametrize("all_pages", [True, False])
def test_fmc_zero_count_without_items_is_verified_empty(assistant, lab, all_pages):
    def empty(request):
        if request.url.path.endswith("networks"):
            return httpx.Response(200, json={"links": {}, "paging": {
                "offset": 0, "limit": 0, "count": 0, "pages": 0}})
    lab.override = empty
    result = assistant.read("lab-fmc-1", "getAllNetworkObject", all_pages=all_pages)
    assert result["result"]["body"]["items"] == []
    assert result["result"]["complete"] is True
    assert assistant.verify("lab-fmc-1", "getAllNetworkObject", {"items": []})["verification"]["status"] == "verified_in_fmc"


@pytest.mark.parametrize("payload", [{}, {"paging": {"count": 1, "pages": 1}},
                                     {"paging": {"count": 0}}, {"paging": {"count": False, "pages": 0}}])
def test_missing_items_without_empty_collection_proof_is_rejected(assistant, lab, payload):
    def malformed(request):
        if request.url.path.endswith("networks"):
            return httpx.Response(200, json=payload)
    lab.override = malformed
    with pytest.raises(AssistantError) as error:
        assistant.read("lab-fmc-1", "getAllNetworkObject")
    assert error.value.code == "pagination_shape_invalid"


def test_registration_defaults_are_local_reusable_and_scoped(assistant, state, lab):
    from concurrent.futures import ThreadPoolExecutor

    from secure_firewall_assistant.state import Device

    for alias in ("lab-ftd-1", "lab-ftd-2"):
        state.save_device(Device(alias, "ftd", "192.0.2.1", "fixture-user", alias + "-auth"))
    def prepare(_):
        return assistant.prepare_registration_key("lab-fmc-1", "lab-ftd-1", "Register the FTD")
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(prepare, range(4)))
    assert sum(r["created"] for r in results) == 1
    assert len({r["reference"] for r in results}) == 1
    first = results[0]
    value = assistant.secrets.get(first["reference"])
    assert len(value) == 32 and all(c in "0123456789abcdef" for c in value)
    assert value not in json.dumps(results)
    assert value not in json.dumps(assistant.evidence.read(first["run_id"]))
    assert first["manager_address"] == "fmc.example.invalid"
    assert assistant.prepare_registration_key("lab-fmc-1", "lab-ftd-2", "Register the FTD")["reference"] != first["reference"]
    assert not lab.calls
    for target, device, request in [("missing", "lab-ftd-1", "Register"),
                                    ("lab-fmc-1", "missing", "Register"),
                                    ("lab-fmc-1", "lab-ftd-1", "")]:
        with pytest.raises(AssistantError):
            assistant.prepare_registration_key(target, device, request)


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


def test_batch_uses_native_bulk_and_one_collection_verification(assistant, lab):
    bodies = [{**NETWORK, "name": f"network-{i}"} for i in range(4)]
    result = assistant.execute_batch("lab-fmc-1", "createMultipleNetworkObject", "Create four networks", bodies)
    assert result["result"]["strategy"] == "native_bulk"
    assert result["result"]["counts"] == {"verified_in_fmc": 4}
    posts = [r for r in lab.calls if r.method == "POST" and r.url.path.endswith("networks")]
    assert len(posts) == 1 and posts[0].url.params["bulk"] == "true"
    gets = [r for r in lab.calls if r.method == "GET" and "/object/networks" in r.url.path]
    assert len(gets) == 1 and gets[0].url.path.endswith("networks")
    assert result["deployment_performed"] is False


def test_batch_preflight_invalid_later_item_prevents_all_writes(assistant, lab):
    with pytest.raises(AssistantError):
        assistant.execute_batch("lab-fmc-1", "createMultipleNetworkObject", "Create networks",
                                [NETWORK, {"type": "Network"}], batch_size=1)
    assert not any(r.method == "POST" and r.url.path.endswith("networks") for r in lab.calls)


@pytest.mark.parametrize("operation", ["createDeploymentRequest", "createBulkCommand", "updateNetworkObject"])
def test_batch_retains_operation_guards(assistant, lab, operation):
    with pytest.raises(AssistantError) as error:
        assistant.execute_batch("lab-fmc-1", operation, "Create resources", [NETWORK])
    assert error.value.code == "operation_guard"
    assert not lab.calls


def test_batch_never_replays_uncertain_bulk_or_sends_next_chunk(assistant, lab):
    def fail(request):
        if request.method == "POST" and request.url.path.endswith("networks"):
            return httpx.Response(503, json={"error": {"messages": []}})
    lab.override = fail
    result = assistant.execute_batch("lab-fmc-1", "createMultipleNetworkObject", "Create networks",
                                     [NETWORK, {**NETWORK, "name": "other"}], batch_size=1)
    assert result["result"]["counts"] == {"reconcile_required": 1, "not_attempted": 1}
    assert result["verification"]["status"] == "partial_or_unverified"
    assert len([r for r in lab.calls if r.method == "POST" and r.url.path.endswith("networks")]) == 1


def test_batch_collection_mismatch_cannot_pass(assistant, lab):
    def lie(request):
        if request.method == "GET" and request.url.path.endswith("networks"):
            return httpx.Response(200, json={"items": []})
    lab.override = lie
    result = assistant.execute_batch("lab-fmc-1", "createMultipleNetworkObject", "Create network", [NETWORK])
    assert result["result"]["counts"] == {"mismatch": 1}


def test_batch_nonbulk_concurrency_is_bounded_and_real(assistant, lab):
    import threading
    # Simulate a catalog operation that genuinely lacks native bulk support.
    op = assistant.catalog.get("createVpnEndpoint")
    op["parameters"] = [p for p in op["parameters"] if p.get("name") != "bulk"]
    active = 0
    maximum = 0
    lock = threading.Lock()
    barrier = threading.Barrier(2)
    def endpoints(request):
        nonlocal active, maximum
        if request.url.path.endswith("endpoints"):
            if request.method == "POST":
                data = json.loads(request.content)
                assert "bulk" not in request.url.params
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                barrier.wait(timeout=5)
                name = data["extranetInfo"]["name"]
                created = {**data, "id": name}
                with lock:
                    lab.objects[name] = created
                    active -= 1
                return httpx.Response(201, json=created)
            return httpx.Response(200, json={"items": list(lab.objects.values()), "paging": {"pages": 1}})
    lab.override = endpoints
    bodies = [{"peerType": "SPOKE", "extranet": True,
               "extranetInfo": {"name": f"spoke-{i}", "ipAddress": f"198.18.0.{i+1}"}} for i in range(4)]
    result = assistant.execute_batch("lab-fmc-1", "createVpnEndpoint", "Create independent spokes", bodies,
                                     path={"containerUUID": "vpn-1"}, max_workers=2)
    assert maximum == 2
    assert result["result"]["counts"] == {"verified_in_fmc": 4}
    assert result["result"]["strategy"] == "bounded_independent_creates"


def test_batch_async_is_pending_not_verified(assistant, lab):
    def pending(request):
        if request.method == "POST" and request.url.path.endswith("networks"):
            return httpx.Response(202, json={"id": "task-1"})
    lab.override = pending
    result = assistant.execute_batch("lab-fmc-1", "createMultipleNetworkObject", "Create network", [NETWORK])
    assert result["result"]["counts"] == {"pending_async": 1}
    assert result["verification"]["status"] != "verified_in_fmc"


def test_vpn_endpoint_batch_uses_native_bulk(assistant, lab):
    def endpoints(request):
        if request.url.path.endswith("endpoints"):
            if request.method == "POST":
                assert request.url.params["bulk"] == "true"
                bodies = json.loads(request.content)
                assert isinstance(bodies, list) and len(bodies) == 2
                for i, body in enumerate(bodies):
                    lab.objects[str(i)] = {**body, "id": str(i)}
                return httpx.Response(201, json={"items": list(lab.objects.values())})
            return httpx.Response(200, json={"items": list(lab.objects.values()), "paging": {"pages": 1}})
    lab.override = endpoints
    bodies = [{"peerType": "SPOKE", "extranet": True,
               "extranetInfo": {"name": f"spoke-{i}", "ipAddress": f"198.18.0.{i+1}"}} for i in range(2)]
    result = assistant.execute_batch("lab-fmc-1", "createVpnEndpoint", "Create independent spokes", bodies,
                                     path={"containerUUID": "vpn-1"})
    assert result["result"]["counts"] == {"verified_in_fmc": 2}
    assert len([r for r in lab.calls if r.method == "POST" and r.url.path.endswith("endpoints")]) == 1


def test_deployment_uses_fresh_timestamp_without_ignoring_pending_changes(assistant, lab):
    preview = assistant.preview_deployment("lab-fmc-1", ["ftd-1"])
    original = assistant._deployment_snapshot
    def fresh(target, identifiers):
        result = original(target, identifiers)
        result["version"] = "12346"
        result["devices"][0]["version"] = "12346"
        return result
    assistant._deployment_snapshot = fresh
    assistant.deploy("lab-fmc-1", preview["preview_id"], "Deploy all", "all_pending_on_selected_devices")
    payload = json.loads(next(r.content for r in lab.calls if r.url.path.endswith("deploymentrequests")))
    assert payload["version"] == "12346"
    preview = assistant.preview_deployment("lab-fmc-1", ["ftd-1"])
    lab.pending.append({"entityUUID": "other", "action": "ADD"})
    with pytest.raises(AssistantError, match="changed"):
        assistant.deploy("lab-fmc-1", preview["preview_id"], "Deploy all", "all_pending_on_selected_devices")
