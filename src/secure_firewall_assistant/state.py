import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from filelock import FileLock
from platformdirs import user_config_path, user_data_path

from .errors import AssistantError

ALIAS = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")


def plugin_root() -> Path:
    package_root = Path(__file__).resolve().parents[2]
    if (package_root / "installation.json").is_file() and package_root.parent.name == "releases":
        return package_root.parent.parent
    return package_root


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)
    return path


def atomic_json(path: Path, value):
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".sfa-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(value, out, indent=2, ensure_ascii=False)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@dataclass(frozen=True)
class Device:
    alias: str
    kind: str
    address: str
    username: str
    credential_ref: str
    domain: str | None = None
    ca_bundle: str | None = None
    expected_version_prefix: str | None = None
    port: int = 22
    fmc_alias: str | None = None
    device_uuid: str | None = None

    def __post_init__(self):
        if not ALIAS.fullmatch(self.alias) or self.kind not in ("fmc", "ftd"):
            raise AssistantError("invalid_device", "Supply a valid device alias and kind (fmc or ftd).")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.credential_ref):
            raise AssistantError("invalid_device", "Username and a valid credential reference are required.")
        if self.kind == "fmc":
            u = urlsplit(self.address)
            try:
                port = u.port
            except ValueError:
                raise AssistantError("invalid_address", "Invalid HTTPS port.") from None
            if (u.scheme != "https" or not u.hostname or u.username or u.password or
                    u.query or u.fragment or u.path not in ("", "/") or (port is not None and port < 1)):
                raise AssistantError("invalid_address", "FMC address must be an HTTPS origin without credentials or a path.")
        elif not re.fullmatch(r"[a-zA-Z0-9_.:\-]+", self.address) or not 1 <= self.port <= 65535:
            raise AssistantError("invalid_address", "FTD address must be an IP address or hostname and a valid SSH port.")


class State:
    def __init__(self, config: Path | None = None, data: Path | None = None,
                 device_file: Path | None = None):
        override = os.environ.get("SFA_DATA_DIR")
        self.config = private_dir(config or (Path(override) / "config" if override else
                                            user_config_path("SecureFirewallAssistant", appauthor=False)))
        self.data = private_dir(data or (Path(override) / "data" if override else
                                       user_data_path("SecureFirewallAssistant", appauthor=False)))
        self.inventory_path = self.config / "inventory.json"
        self.device_file = device_file or plugin_root() / "devices.yaml"

    def inventory(self) -> dict:
        try:
            obj = (json.loads(self.inventory_path.read_text(encoding="utf-8"))
                   if self.inventory_path.exists() else {"format_version": 1, "devices": {}})
            if obj.get("format_version") != 1 or not isinstance(obj["devices"], dict):
                raise ValueError
            for name, fields in obj["devices"].items():
                if name != Device(**fields).alias:
                    raise ValueError
            if self.device_file.exists():
                local = yaml.safe_load(self.device_file.read_text(encoding="utf-8"))
                if (not isinstance(local, dict) or local.get("format_version") != 1 or
                        not isinstance(local.get("devices", {}), dict)):
                    raise ValueError
                for name, fields in local.get("devices", {}).items():
                    if "device_name" in fields:
                        from .enrollment_ui import validate_row
                        row = validate_row({key: fields[key] for key in
                                            ("device_name", "hostname", "https_port", "ssh_port")})
                        if row["device_name"] != name:
                            raise ValueError
                        runtime = {key: value for key, value in fields.items()
                                   if key not in ("device_name", "hostname", "https_port", "ssh_port", "password")}
                        host = f'[{row["hostname"]}]' if ":" in row["hostname"] else row["hostname"]
                        kind = runtime.get("kind", "fmc")
                        runtime.update(alias=name, kind=kind, port=row["ssh_port"],
                                       address=f'https://{host}:{row["https_port"]}' if kind == "fmc" else row["hostname"])
                        runtime.setdefault("username", "")
                        runtime.setdefault("credential_ref", name + "-auth")
                        device = Device(**runtime)
                    else:
                        device = Device(**{key: value for key, value in fields.items() if key != "password"})
                    if name != device.alias:
                        raise ValueError
                    # Only validated metadata enters the in-memory inventory;
                    # credential values remain in the local YAML store.
                    obj["devices"][name] = asdict(device)
            return obj
        except (OSError, UnicodeError, yaml.YAMLError, ValueError, TypeError, KeyError):
            raise AssistantError("inventory_invalid", "Inventory is invalid or uses an unsupported format; restore its backup.") from None

    def save_device(self, device: Device):
        with FileLock(str(self.config / "inventory.lock"), timeout=15):
            obj = self.inventory()
            if self.inventory_path.exists():
                atomic_json(self.config / "inventory.backup.json", obj)
            obj["devices"][device.alias] = asdict(device)
            atomic_json(self.inventory_path, obj)

    def device(self, alias: str, kind: str | None = None) -> Device:
        obj = self.inventory()["devices"]
        if alias not in obj:
            raise AssistantError("unknown_target", "Select an enrolled target by exact alias.", available_aliases=sorted(obj))
        device = Device(**obj[alias])
        if kind and device.kind != kind:
            raise AssistantError("wrong_target_kind", f"This tool requires an enrolled {kind.upper()}.")
        if not device.username:
            raise AssistantError("credential_missing", "This inventory device has no local account configured. Configure credentials locally before connecting.")
        return device

    def aliases(self) -> list[dict]:
        return [{"alias": d["alias"], "kind": d["kind"], "domain": d.get("domain"),
                 "fmc_alias": d.get("fmc_alias")} for d in self.inventory()["devices"].values()]

    def target_lock(self, alias: str) -> FileLock:
        if not ALIAS.fullmatch(alias):
            raise AssistantError("invalid_target", "Invalid target alias.")
        return FileLock(str(self.data / f"target-{alias}.lock"), timeout=20)
