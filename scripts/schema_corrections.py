"""Maintained corrections to omissions in the supplied FMC OpenAPI document."""

VPN_ENDPOINT_PATH = "/api/fmc_config/v1/domain/{domainUUID}/policy/ftds2svpns/{containerUUID}/endpoints"
CORRECTION_NOTE = (
    "Declared createVpnEndpoint bulk query and single/array request bodies; "
    "bulk support confirmed by the project owner (2026-10-21)"
)


def apply_corrections(document):
    operation = document["paths"][VPN_ENDPOINT_PATH]["post"]
    parameters = operation["parameters"]
    if not any(p.get("name") == "bulk" and p.get("in") == "query" for p in parameters):
        parameters.append({"name": "bulk", "in": "query", "required": False,
                           "schema": {"type": "boolean", "default": False},
                           "description": "Set true to create multiple VPN endpoints with an array body."})
    operation["requestBody"]["content"]["application/json"]["schema"] = {
        "oneOf": [{"$ref": "#/components/schemas/VpnEndpoint"},
                  {"type": "array", "items": {"$ref": "#/components/schemas/VpnEndpoint"}}]}
    operation["description"] = (
        "Create one endpoint in a Site to Site VPN topology, or multiple endpoints "
        "with bulk=true and an array of VpnEndpoint objects. Single creates use an object body."
    )
