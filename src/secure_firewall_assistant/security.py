import os
import re
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml
from filelock import FileLock

from .errors import AssistantError
from .inventory import grouped_inventory, normalize_inventory
from .state import Device, plugin_root

SENSITIVE = re.compile(
    r"password|passwd|secret|token|authorization|cookie|private.?key|community|pre.?shared|credential",
    re.I,
)
REFERENCE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")


def sensitive(key: str) -> bool:
    return bool(SENSITIVE.search(key))


class Redactor:
    def __init__(self):
        self.values: set[str] = set()

    def register(self, value: str | None):
        if value:
            self.values.add(value)

    def clean(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            named_secret = any(isinstance(obj.get(k), str) and sensitive(obj[k])
                               for k in ("field", "fieldName", "attribute", "property"))
            return {str(k): "[REDACTED]" if sensitive(str(k)) or (
                named_secret and k in {"value", "oldValue", "newValue", "before", "after"})
                else self.clean(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.clean(v) for v in obj]
        if isinstance(obj, str):
            for value in sorted(self.values, key=len, reverse=True):
                obj = obj.replace(value, "[REDACTED]")
            obj = re.sub(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z]+ )?PRIVATE KEY-----",
                         "[REDACTED PRIVATE KEY]", obj, flags=re.S)
            obj = re.sub(r"(?im)^.*\b(?:password|passwd|secret|token|authorization|cookie|community|pre-shared-key)\b\s*[:=]\s*\S.*$",
                         "[REDACTED SENSITIVE LINE]", obj)
        return obj


class SecretStore:
    """Store local lab credentials and device metadata in the ignored plugin YAML file."""

    def __init__(self, redactor: Redactor, path: Path | None = None):
        self.redactor = redactor
        self.path = path or plugin_root() / "devices.yaml"

    def _read(self) -> dict:
        if not self.path.exists():
            return {"format_version": 1, "devices": {}}
        try:
            return normalize_inventory(yaml.safe_load(self.path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, yaml.YAMLError, ValueError, TypeError):
            raise AssistantError("credential_file_invalid", "The local devices.yaml file is invalid; repair it from the sample file.") from None

    def _write(self, value: dict):
        if self.path.exists():
            backup = self.path.with_name(".sfa-devices-pre-grouped.backup")
            if not backup.exists():
                fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as out:
                    out.write(self.path.read_bytes())
        # Migrate legacy login references into each device; retain API-only secrets.
        if value.get("credentials") and self.path.exists():
            backup = self.path.with_name(".sfa-devices-pre-inline.backup")
            if not backup.exists():
                fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as out:
                    out.write(self.path.read_bytes())
        legacy = {**value.pop("credentials", {}), **value.pop("secrets", {})}
        consumed = set()
        for name, record in value["devices"].items():
            reference = record.get("credential_ref", name + "-auth")
            if reference in legacy:
                if not record.get("password"):
                    record["password"] = legacy[reference]
                consumed.add(reference)
            record.setdefault("username", "")
            record.setdefault("password", "")
        remaining = {key: item for key, item in legacy.items() if key not in consumed}
        if remaining:
            value["secrets"] = remaining
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".sfa-devices-", suffix=".tmp")
        try:
            if os.name != "nt":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                yaml.safe_dump(grouped_inventory(value), out, sort_keys=False, allow_unicode=True)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, self.path)
            if os.name != "nt":
                self.path.chmod(0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def get(self, reference: str) -> str:
        self._check(reference)
        try:
            with FileLock(str(self.path) + ".lock", timeout=15):
                stored = self._read()
                value = next((record.get("password") for name, record in stored["devices"].items()
                              if record.get("credential_ref", name + "-auth") == reference), None)
                value = value or stored.get("secrets", {}).get(reference) or stored.get("credentials", {}).get(reference)
        except AssistantError:
            raise
        except Exception:
            raise AssistantError("credential_file_unavailable", "The local devices.yaml file could not be read.") from None
        if not value:
            raise AssistantError("credential_missing", "Configure this credential locally through hidden terminal entry.")
        self.redactor.register(value)
        return value

    def set(self, reference: str, value: str, device: Device | None = None):
        self._check(reference)
        if not value:
            raise AssistantError("empty_credential", "A credential must not be empty.")
        self.redactor.register(value)
        try:
            with FileLock(str(self.path) + ".lock", timeout=15):
                stored = self._read()
                if device is not None:
                    from urllib.parse import urlsplit
                    origin = urlsplit(device.address) if device.kind == "fmc" else None
                    record = stored["devices"].get(device.alias, {}).copy()
                    record.update(asdict(device))
                    record.update(device_name=device.alias, hostname=origin.hostname if origin else device.address,
                                  https_port=(origin.port or 443) if origin else record.get("https_port", 443),
                                  ssh_port=device.port, password=value)
                    stored["devices"][device.alias] = record
                else:
                    matches = [record for name, record in stored["devices"].items()
                               if record.get("credential_ref", name + "-auth") == reference]
                    if matches:
                        for record in matches:
                            record["password"] = value
                    else:
                        stored.setdefault("secrets", {})[reference] = value
                self._write(stored)
        except Exception:
            raise AssistantError("credential_file_write_failed", "The local devices.yaml file could not be saved.") from None

    @staticmethod
    def _check(reference: str):
        if not REFERENCE.fullmatch(reference):
            raise AssistantError("invalid_secret_reference", "Credential references use letters, digits, dots, underscores, and hyphens.")

    def resolve(self, value: Any, key: str = "") -> Any:
        if isinstance(value, dict) and "$secret" in value:
            if set(value) != {"$secret"} or not isinstance(value["$secret"], str):
                raise AssistantError("invalid_secret_reference", "Use an object containing only $secret and a local reference.")
            return self.get(value["$secret"])
        if sensitive(key) and value is not None and value != "" and not isinstance(value, bool):
            raise AssistantError("literal_secret_rejected", "Use a locally enrolled $secret reference for sensitive fields.")
        if isinstance(value, dict):
            return {k: self.resolve(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [self.resolve(v, key) for v in value]
        return value
