"""Device inventory MCP App. Uses the host bridge; no network listener or credentials."""
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from filelock import FileLock
from mcp.types import CallToolResult, TextContent

from .errors import AssistantError
from .state import ALIAS

MIME = "text/html;profile=mcp-app"


def validate_row(row):
    if not isinstance(row, dict) or set(row) != {"device_name", "hostname", "https_port", "ssh_port"}:
        raise AssistantError("invalid_inventory", "Each device requires Device Name, Hostname/IP Address, HTTPS port, and SSH port.")
    name, host = row["device_name"], row["hostname"]
    if not isinstance(name, str) or not ALIAS.fullmatch(name):
        raise AssistantError("invalid_inventory", "Device names must use 1–64 letters, digits, dots, underscores, or hyphens, starting with a letter or digit.")
    if not isinstance(host, str) or not host or len(host) > 253:
        raise AssistantError("invalid_inventory", "Enter a hostname or IP address without a URL scheme, path, or port.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                   for part in host.rstrip(".").split(".")):
            raise AssistantError("invalid_inventory", "Enter a valid hostname or IP address without a URL scheme, path, or port.") from None
    if any(type(row[key]) is not int or not 1 <= row[key] <= 65535 for key in ("https_port", "ssh_port")):
        raise AssistantError("invalid_inventory", "HTTPS and SSH ports must be whole numbers from 1 to 65535.")
    return dict(row)


class EnrollmentUI:
    """Compatibility class name for the former enrollment resource."""

    def __init__(self, state, store):
        self.state, self.store = state, store
        self.uri = "ui://secure-firewall/device-inventory/v1.html"

    def close(self):
        pass

    @property
    def resource_meta(self):
        return {"ui": {"prefersBorder": True, "csp": {"connectDomains": [], "resourceDomains": []}},
                "openai/widgetDescription": "Edit device names, hostnames/IP addresses, HTTPS ports, and SSH ports in the local device inventory YAML.",
                "openai/widgetCSP": {"connect_domains": [], "resource_domains": []}}

    def rows(self):
        rows = []
        for name, device in self.state.inventory()["devices"].items():
            origin = urlsplit(device["address"]) if device["kind"] == "fmc" else None
            rows.append({"device_name": name, "hostname": origin.hostname if origin else device["address"],
                         "https_port": (origin.port or 443) if origin else 443,
                         "ssh_port": device.get("port", 22)})
        # Preserve HTTPS metadata on FTD entries too.
        local = self.store._read()["devices"]
        for row in rows:
            stored = local.get(row["device_name"], {})
            row["https_port"] = stored.get("https_port", row["https_port"])
        return rows

    def start(self, alias="", address=""):
        rows = self.rows()
        if alias and not any(row["device_name"] == alias for row in rows):
            origin = urlsplit(address) if "://" in address else None
            rows.append({"device_name": alias, "hostname": (origin.hostname or "") if origin else address,
                         "https_port": (origin.port or 443) if origin else 443, "ssh_port": 22})
        public = {"status": "edit_device_inventory", "devices": rows,
                  "next_step": "Edit the device inventory form and select Save inventory. This only updates devices.yaml."}
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(public))], structured_content=public)

    def save(self, devices):
        if not isinstance(devices, list) or not 1 <= len(devices) <= 1000:
            raise AssistantError("invalid_inventory", "Submit between 1 and 1000 devices.")
        rows = [validate_row(row) for row in devices]
        if len({row["device_name"] for row in rows}) != len(rows):
            raise AssistantError("invalid_inventory", "Device names must be unique.")
        # Validate every row before writing, and share the credential writer's lock.
        with FileLock(str(self.store.path) + ".lock", timeout=15):
            stored = self.store._read()
            existing = self.state.inventory()["devices"]
            for row in rows:
                name = row["device_name"]
                record = stored["devices"].get(name, existing.get(name, {})).copy()
                record.update(row)
                if "address" in record:
                    host = f'[{row["hostname"]}]' if ":" in row["hostname"] else row["hostname"]
                    record["address"] = (f'https://{host}:{row["https_port"]}'
                                         if record.get("kind") == "fmc" else row["hostname"])
                    record["port"] = row["ssh_port"]
                stored["devices"][name] = record
            self.store._write(stored)
        return {"ok": True, "status": "inventory_saved", "devices": rows,
                "message": "Device inventory saved to devices.yaml."}

    def html(self):
        return Path(__file__).with_name("enrollment_card.html").read_text(encoding="utf-8")
