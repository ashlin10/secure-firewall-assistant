import re
import sys
from typing import Any

from .errors import AssistantError

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
    """Select a native backend explicitly; never accept plaintext fallback backends."""

    service = "com.secure-firewall-assistant.credentials.v1"

    def __init__(self, redactor: Redactor):
        self.redactor = redactor
        self._backend = None

    @property
    def backend(self):
        if self._backend is None:
            try:
                if sys.platform == "darwin":
                    from keyring.backends.macOS import Keyring
                elif sys.platform == "win32":
                    from keyring.backends.Windows import WinVaultKeyring as Keyring
                else:
                    raise AssistantError("unsupported_os", "This release supports macOS and Windows only.")
                self._backend = Keyring()
            except AssistantError:
                raise
            except Exception:
                raise AssistantError("secret_store_unavailable", "The native credential store is unavailable.") from None
        return self._backend

    def get(self, reference: str) -> str:
        self._check(reference)
        try:
            value = self.backend.get_password(self.service, reference)
        except AssistantError:
            raise
        except Exception:
            raise AssistantError("secret_store_locked", "Unlock or repair the native credential store locally.") from None
        if not value:
            raise AssistantError("credential_missing", "Enroll this credential with the local enrollment utility.")
        self.redactor.register(value)
        return value

    def set(self, reference: str, value: str):
        self._check(reference)
        if not value:
            raise AssistantError("empty_credential", "A credential must not be empty.")
        self.redactor.register(value)
        try:
            self.backend.set_password(self.service, reference, value)
        except Exception:
            raise AssistantError("secret_store_write_failed", "The native credential store could not save the credential.") from None

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
