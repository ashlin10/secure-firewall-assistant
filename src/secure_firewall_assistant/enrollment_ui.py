"""Device inventory MCP App. Uses the host bridge; no network listener."""
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from filelock import FileLock
from mcp.types import CallToolResult, TextContent

from .errors import AssistantError
from .inventory import DEVICE_TYPES
from .state import ALIAS, atomic_json

MIME = "text/html;profile=mcp-app"


def validate_row(row):
    required = {"device_name", "hostname", "https_port", "ssh_port"}
    if not isinstance(row, dict) or not required <= set(row) or set(row) - required - {"username", "password", "device_type"}:
        raise AssistantError("invalid_inventory", "Each device requires Device Name, Hostname/IP Address, HTTPS port, and SSH port.")
    name, host = row["device_name"], row["hostname"]
    if row.get("device_type", "fmc") not in DEVICE_TYPES:
        raise AssistantError("invalid_inventory", "Select a supported device type.")
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
    for key in ("username", "password"):
        if key in row and (not isinstance(row[key], str) or len(row[key]) > 4096):
            raise AssistantError("invalid_inventory", "Username and password must be text of at most 4096 characters.")
    if row.get("password") and not row.get("username"):
        raise AssistantError("invalid_inventory", "Enter a username when setting a password.")
    return dict(row)


class EnrollmentUI:
    """Compatibility class name for the former enrollment resource."""

    def __init__(self, state, store):
        self.state, self.store = state, store
        self.uri = "ui://secure-firewall/device-inventory/v1.html"
        self.enrollment_uri = "ui://secure-firewall/add-devices/v1.html"

    def close(self):
        pass

    @property
    def resource_meta(self):
        return {"ui": {"prefersBorder": True, "csp": {"connectDomains": [], "resourceDomains": []}},
                "openai/widgetDescription": "Edit device details, usernames, and passwords, or delete devices from the local inventory YAML.",
                "openai/widgetCSP": {"connect_domains": [], "resource_domains": []}}

    def rows(self):
        rows = []
        for name, device in self.state.inventory()["devices"].items():
            origin = urlsplit(device["address"]) if device["kind"] == "fmc" else None
            rows.append({"device_name": name, "device_type": device["kind"], "hostname": origin.hostname if origin else device["address"],
                         "https_port": (origin.port or 443) if origin else 443,
                         "ssh_port": device.get("port", 22), "username": device.get("username", ""),
                         "has_account": self._has_account(name, device)})
        # Preserve HTTPS metadata on FTD entries too.
        local = self.store._read()["devices"]
        for row in rows:
            stored = local.get(row["device_name"], {})
            row["https_port"] = stored.get("https_port", row["https_port"])
        return rows

    def _has_account(self, name, device):
        stored = self.store._read()
        reference = device.get("credential_ref", name + "-auth")
        return bool(stored["devices"].get(name, {}).get("password") or
                    stored.get("credentials", {}).get(reference) or stored.get("secrets", {}).get(reference))

    def start(self, alias="", address="", kind="fmc", *, new_only=False):
        rows = [] if new_only else self.rows()
        if alias and not any(row["device_name"] == alias for row in rows):
            origin = urlsplit(address) if "://" in address else None
            rows.append({"device_name": alias, "device_type": kind, "hostname": (origin.hostname or "") if origin else address,
                         "https_port": (origin.port or 443) if origin else 443, "ssh_port": 22,
                         "username": "", "has_account": False})
        public = {"status": "enroll_devices" if new_only else "edit_device_inventory", "devices": rows,
                  "next_step": ("Add new devices and select Save new devices." if new_only else
                                "Edit the device inventory form and select Save inventory.") +
                               " This only updates devices.yaml."}
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(public))], structured_content=public)

    def save(self, devices, deleted_devices=None, *, new_only=False):
        if not isinstance(devices, list) or not 0 <= len(devices) <= 1000:
            raise AssistantError("invalid_inventory", "Submit up to 1000 devices.")
        rows = [validate_row(row) for row in devices]
        if len({row["device_name"] for row in rows}) != len(rows):
            raise AssistantError("invalid_inventory", "Device names must be unique.")
        deleted_devices = [] if deleted_devices is None else deleted_devices
        if new_only and (deleted_devices or not rows):
            raise AssistantError("invalid_inventory", "Enrollment requires new devices and cannot delete saved devices.")
        if (not isinstance(deleted_devices, list) or len(deleted_devices) > 1000 or
                any(not isinstance(name, str) or not ALIAS.fullmatch(name) for name in deleted_devices) or
                set(deleted_devices) & {row["device_name"] for row in rows}):
            raise AssistantError("invalid_inventory", "Deleted devices must be valid names absent from the saved rows.")
        # Validate every row before writing, and share the credential writer's lock.
        with FileLock(str(self.store.path) + ".lock", timeout=15), \
                FileLock(str(self.state.config / "inventory.lock"), timeout=15):
            stored = self.store._read()
            existing = self.state.inventory()["devices"]
            if new_only and any(row["device_name"] in existing or row["device_name"] in stored["devices"] for row in rows):
                raise AssistantError("device_exists", "A device name is already enrolled. Choose a new name or open device inventory to edit it.")
            # Bring legacy metadata into YAML before migrating its credential references.
            for name, device in existing.items():
                stored["devices"].setdefault(name, device.copy())
            for name in deleted_devices:
                record = stored["devices"].pop(name, {})
                reference = record.get("credential_ref", name + "-auth")
                if not any(device.get("credential_ref", alias + "-auth") == reference
                           for alias, device in stored["devices"].items()):
                    for section in ("credentials", "secrets"):
                        stored.get(section, {}).pop(reference, None)
            for row in rows:
                name = row["device_name"]
                record = stored["devices"].get(name, existing.get(name, {})).copy()
                update = dict(row)
                record["kind"] = update.pop("device_type", record.get("kind", "fmc"))
                if not update.get("password"):
                    update.pop("password", None)
                record.update(update)
                if "address" in record:
                    host = f'[{row["hostname"]}]' if ":" in row["hostname"] else row["hostname"]
                    record["address"] = (f'https://{host}:{row["https_port"]}'
                                         if record.get("kind") == "fmc" else row["hostname"])
                    record["port"] = row["ssh_port"]
                stored["devices"][name] = record
            legacy_before = None
            if deleted_devices and self.state.inventory_path.exists():
                legacy_before = json.loads(self.state.inventory_path.read_text(encoding="utf-8"))
                legacy = {**legacy_before, "devices": {name: device for name, device in legacy_before["devices"].items()
                                                     if name not in deleted_devices}}
                atomic_json(self.state.inventory_path, legacy)
            try:
                self.store._write(stored)
            except Exception:
                if legacy_before is not None:
                    atomic_json(self.state.inventory_path, legacy_before)
                raise
        return {"ok": True, "status": "inventory_saved", "devices":
                ([{"device_name": row["device_name"]} for row in rows] if new_only else self.rows()),
                "message": "Device inventory saved to devices.yaml."}

    def html(self, *, new_only=False):
        html = Path(__file__).with_name("enrollment_card.html").read_text(encoding="utf-8")
        if new_only:
            html = html.replace("const enrollmentOnly=false;", "const enrollmentOnly=true;")
            html = html.replace("Device inventory", "Add devices").replace("Save inventory", "Save new devices")
            html = html.replace("Loading device inventory…", "Loading enrollment form…")
        return html
