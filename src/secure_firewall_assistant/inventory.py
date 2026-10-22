"""Versioned device YAML; the runtime uses a flat, validated alias index."""
import copy
from urllib.parse import urlsplit

DEVICE_TYPES = ("fmc", "ftd", "endpoints", "traffic_generators", "routers", "switches")


def normalize_inventory(value):
    if not isinstance(value, dict) or value.get("format_version") not in (1, 2, 3):
        raise ValueError("Unsupported inventory format")
    result = copy.deepcopy(value)
    if value["format_version"] == 1:
        devices = result.setdefault("devices", {})
    elif value["format_version"] == 3:
        if set(value) - {"format_version", "devices", "secrets", "credentials"}:
            raise ValueError("Unknown inventory section")
        sections = result.get("devices", {})
        if not isinstance(sections, dict) or set(sections) - set(DEVICE_TYPES):
            raise ValueError("Unknown device section")
        devices = {}
        for kind, records in sections.items():
            if not isinstance(records, list):
                raise ValueError("Device sections must be lists")
            for record in records:
                if not isinstance(record, dict):
                    raise ValueError("Invalid device record")
                alias = record.get("device_name")
                if (not isinstance(alias, str) or not alias or alias in devices or
                        record.get("kind", kind) != kind):
                    raise ValueError("Duplicate alias or conflicting device type")
                devices[alias] = {**record, "kind": kind}
    else:
        if set(value) - {"format_version", "secrets", "credentials", *DEVICE_TYPES}:
            raise ValueError("Unknown inventory section")
        devices = {}
        for kind in DEVICE_TYPES:
            records = result.pop(kind, {})
            if not isinstance(records, dict):
                raise ValueError("Device sections must be mappings")
            for alias, record in records.items():
                if alias in devices or not isinstance(record, dict) or record.get("kind", kind) != kind:
                    raise ValueError("Duplicate alias or conflicting device type")
                devices[alias] = {**record, "kind": kind}
    if not isinstance(devices, dict) or any(not isinstance(k, str) or not isinstance(v, dict)
                                            for k, v in devices.items()):
        raise ValueError("Invalid device mapping")
    for record in devices.values():
        if record.get("kind", "fmc") not in DEVICE_TYPES:
            raise ValueError("Unknown device type")
    for section in ("credentials", "secrets"):
        records = result.get(section, {})
        if not isinstance(records, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                                for k, v in records.items()):
            raise ValueError("Invalid secret mapping")
    result.update(format_version=1, devices=devices)
    return result


def grouped_inventory(value):
    value = normalize_inventory(value)
    result = {"format_version": 3, "devices": {kind: [] for kind in DEVICE_TYPES}}
    for alias, record in value["devices"].items():
        kind = record.get("kind", "fmc")
        record = record.copy()
        if "hostname" not in record:
            address = record.get("address", "")
            origin = urlsplit(address) if kind == "fmc" else None
            record.update(hostname=origin.hostname if origin else address,
                          https_port=(origin.port or 443) if origin else 443,
                          ssh_port=record.get("port", 22))
        result["devices"][kind].append({"device_name": alias, **{
            key: item for key, item in record.items() if key not in {"kind", "device_name"}}})
    for section in ("credentials", "secrets"):
        if value.get(section):
            result[section] = value[section]
    return result
