import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from secure_firewall_assistant.catalog import DATA, Catalog
from secure_firewall_assistant.errors import AssistantError


@pytest.fixture(scope="module")
def catalog():
    return Catalog()


def test_schema_integrity_and_discovery(catalog):
    assert len(catalog.operations) == 1623
    assert len(catalog.doc["paths"]) == 889
    assert len(catalog.doc["components"]["schemas"]) == 4052
    assert catalog.provenance["unresolved_references"] == ["#/components/schemas/HADCStateUnavailableResponse"]
    encoded = gzip.decompress((DATA / "fmc.openapi.json.gz").read_bytes())
    assert hashlib.sha256(encoded).hexdigest() == catalog.provenance["sanitized_sha256"]
    assert b'"examples":' not in encoded and b'"example":' not in encoded
    result = catalog.search("networks", "post")
    assert result["operations"][0]["id"] == "createMultipleNetworkObject"
    assert catalog.search("network objects", "post")["total"] >= 1


def test_referenced_body_validation_and_semantic_constraints(catalog):
    result = catalog.prepare("createMultipleNetworkObject", {}, {}, {},
                             {"name": "branch", "type": "Network", "value": "192.0.2.0/24"}, "domain-1")
    assert "/domain/domain-1/" in result["path"]
    with pytest.raises(AssistantError, match="does not satisfy"):
        catalog.prepare("createMultipleNetworkObject", {}, {}, {}, {"type": "NotAnObject"}, "domain-1")
    with pytest.raises(AssistantError, match="name and value"):
        catalog.prepare("createMultipleNetworkObject", {}, {}, {}, {"type": "Network"}, "domain-1")
    with pytest.raises(AssistantError, match="valid address"):
        catalog.prepare("createMultipleNetworkObject", {}, {}, {},
                        {"name": "branch", "type": "Network", "value": "invalid"}, "domain-1")


@pytest.mark.parametrize("params,query,headers,code", [
    ({"domainUUID": "other"}, {}, {}, "domain_mismatch"),
    ({"objectId": "../other"}, {}, {}, "unknown_parameter"),
    ({}, {"limit": True}, {}, "request_validation_failed"),
    ({}, {"unlisted": "value"}, {}, "unknown_parameter"),
    ({}, {}, {"Authorization": "sentinel"}, "unknown_parameter"),
])
def test_parameter_boundary(catalog, params, query, headers, code):
    with pytest.raises(AssistantError) as error:
        catalog.prepare("getAllNetworkObject", params, query, headers, None, "domain-1")
    assert error.value.code == code


@pytest.mark.parametrize("identifier", ["../x", "a/b", "%2e%2e", "x?y", "x#z", "https://other.invalid"])
def test_path_traversal_is_rejected(catalog, identifier):
    with pytest.raises(AssistantError):
        catalog.prepare("getNetworkObject", {"objectId": identifier}, {}, {}, None, "domain-1")


def test_bulk_requires_matching_query_and_array(catalog):
    body = [{"name": "branch", "type": "Network", "value": "192.0.2.0/24"}]
    with pytest.raises(AssistantError) as error:
        catalog.prepare("createMultipleNetworkObject", {}, {}, {}, body, "domain-1")
    assert error.value.code == "bulk_flag_required"
    catalog.prepare("createMultipleNetworkObject", {}, {"bulk": True}, {}, body, "domain-1")


def test_bad_reference_is_not_fabricated(catalog):
    assert catalog.validate({"$ref": "#/components/schemas/HADCStateUnavailableResponse"}, {}, response=True)
    with pytest.raises(AssistantError) as error:
        catalog.validate({"$ref": "https://outside.invalid/schema"}, {})
    assert error.value.code == "schema_validation_unavailable"


def test_errors_never_contain_rejected_payload_values(catalog):
    sentinel = "SYNTHETIC-SENSITIVE-VALUE"
    with pytest.raises(AssistantError) as error:
        catalog.validate({"type": "integer"}, sentinel)
    assert sentinel not in json.dumps(error.value.result())


def test_execution_options_cover_all_methods_and_corrected_endpoint_bulk(catalog):
    counts = {}
    for method in ("post", "put", "delete"):
        page = catalog.search(method=method, bulk_only=True)
        counts[method] = page["total"]
        assert all(o["execution_options"]["bulk_parameter"] for o in page["operations"])
    assert counts == {"post": 55, "put": 19, "delete": 41}
    assert catalog.options("createMultipleNetworkObject")["bulk_create_supported"] is True
    assert catalog.describe("createVpnEndpoint")["execution_options"]["bulk_create_supported"] is True
    assert catalog.options("getAllNetworkObject")["pagination"] == {
        "supported": True, "expanded": True, "filter": True}


def test_vpn_endpoint_bulk_validation(catalog):
    path = {"containerUUID": "topology-1"}
    endpoint = {"type": "VpnEndpoint"}
    catalog.prepare("createVpnEndpoint", path, {}, {}, endpoint, "domain-1")
    result = catalog.prepare("createVpnEndpoint", path, {"bulk": True}, {}, [endpoint, endpoint], "domain-1")
    assert result["query"] == {"bulk": True}
    for body, query, code in [([endpoint], {}, "bulk_flag_required"),
                              (endpoint, {"bulk": True}, "bulk_array_required"),
                              ([42], {"bulk": True}, "request_validation_failed")]:
        with pytest.raises(AssistantError) as error:
            catalog.prepare("createVpnEndpoint", path, query, {}, body, "domain-1")
        assert error.value.code == code
    assert any(op["id"] == "createVpnEndpoint" for op in
               catalog.search("endpoints", "post", bulk_only=True)["operations"])


def test_registration_collection_is_executable_without_opening_special_operations(catalog):
    operation = catalog.describe('createMultipleDevice')
    assert operation['effect'] == 'configuration'
    assert operation['execution_available'] is True
    assert operation['execution_options']['bulk_create_supported'] is True
    assert catalog.describe('createBulkRegistration')['execution_available'] is False
    assert catalog.describe('deleteMultipleDevice')['execution_available'] is False


@pytest.mark.parametrize("interface_type", ["VTI", "PhysicalInterface", "SubInterface"])
def test_vpn_endpoint_interface_types_for_create_bulk_and_update(catalog, interface_type):
    endpoint = {
        "device": {"id": "device-1", "type": "Device"},
        "interface": {"id": "interface-1", "name": "vpn-interface", "type": interface_type},
        "peerType": "PEER", "connectionType": "BIDIRECTIONAL", "extranet": False,
    }
    path = {"containerUUID": "topology-1"}
    catalog.prepare("createVpnEndpoint", path, {}, {}, endpoint, "domain-1")
    catalog.prepare("createVpnEndpoint", path, {"bulk": True}, {}, [endpoint], "domain-1")
    catalog.prepare("updateVpnEndpoint", {**path, "objectId": "endpoint-1"}, {}, {},
                    {**endpoint, "id": "endpoint-1"}, "domain-1")
    assert not catalog.validate_response("createVpnEndpoint", 201, endpoint)


def test_vpn_vti_correction_preserves_reference_constraints(catalog):
    spec = importlib.util.spec_from_file_location(
        "schema_corrections", Path(__file__).resolve().parents[1] / "scripts/schema_corrections.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    apply_corrections = module.apply_corrections

    document = json.loads(json.dumps(catalog.doc))
    document["components"]["schemas"]["VpnEndpointInterfaceReference"]["properties"]["type"]["enum"].remove("VTI")
    apply_corrections(document)
    apply_corrections(document)
    schemas = document["components"]["schemas"]
    reference = schemas["VpnEndpointInterfaceReference"]
    assert reference["properties"]["type"]["enum"].count("VTI") == 1
    for value in ({"id": "intf", "type": "InventedInterface"}, {"type": "VTI"}):
        with pytest.raises(AssistantError):
            catalog.validate(reference, value)
    with pytest.raises(AssistantError):
        catalog.validate(schemas["VpnEndpointTunnelSourceInterfaceReference"], {"id": "intf", "type": "VTI"})


def test_ha_configuration_is_executable_without_namespace_restriction(catalog):
    for operation in ("createFTDHADeviceContainer", "updateFTDHADeviceContainer",
                      "deleteFTDHADeviceContainer", "updateFTDHAMonitoredInterfaces"):
        assert catalog.describe(operation)["effect"] == "configuration"
        assert catalog.describe(operation)["execution_available"] is True
    assert catalog.describe("createDeploymentRequest")["effect"] == "deployment"
