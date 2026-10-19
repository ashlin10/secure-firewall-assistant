import json
import re
import uuid
from datetime import datetime, timezone

from .errors import AssistantError
from .security import Redactor
from .state import State, atomic_json, private_dir


class Evidence:
    def __init__(self, state: State, redactor: Redactor):
        self.directory = private_dir(state.data / "evidence")
        self.redactor = redactor

    def save(self, event: dict) -> dict:
        run_id = str(uuid.uuid4())
        record = self.redactor.clean({"run_id": run_id, "timestamp": datetime.now(timezone.utc).isoformat(), **event})
        atomic_json(self.directory / f"{run_id}.json", record)
        return record

    def read(self, run_id: str, offset: int = 0, limit: int = 20, pointer: str = "") -> dict:
        if not re.fullmatch(r"[a-f0-9-]{36}", run_id):
            raise AssistantError("invalid_evidence_id", "Supply a run ID returned by this assistant.")
        try:
            record = json.loads((self.directory / f"{run_id}.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise AssistantError("evidence_missing", "This evidence record is not present on this computer.") from None
        if pointer:
            if not pointer.startswith("/") or len(pointer) > 1000:
                raise AssistantError("invalid_evidence_pointer", "Use a JSON pointer beginning with /.")
            try:
                selected = record
                for part in pointer[1:].split("/"):
                    key = part.replace("~1", "/").replace("~0", "~")
                    selected = selected[int(key)] if isinstance(selected, list) else selected[key]
            except (KeyError, IndexError, ValueError, TypeError):
                raise AssistantError("evidence_pointer_missing", "That field is not present in the evidence record.") from None
            return self.redactor.clean({"run_id": run_id, "pointer": pointer, "value": selected})
        body = record.get("result", {}).get("body")
        if isinstance(body, dict) and isinstance(body.get("items"), list):
            items = body["items"]
            offset, limit = max(0, offset), max(1, min(50, limit))
            body["items"] = items[offset:offset + limit]
            record["evidence_page"] = {"offset": offset, "total": len(items),
                                       "next_offset": offset + limit if offset + limit < len(items) else None}
        return self.redactor.clean(record)


def compare(expected, actual, exact: bool = False, path: str = "") -> list:
    """Object keys may be a subset; lists always compare length and order."""
    failures = []
    if isinstance(expected, dict) and isinstance(actual, dict):
        if exact and set(expected) != set(actual):
            failures.append({"path": path, "reason": "different_keys"})
        for key, value in expected.items():
            child = path + "/" + str(key).replace("~", "~0").replace("/", "~1")
            if key not in actual:
                failures.append({"path": child, "reason": "missing"})
            else:
                failures.extend(compare(value, actual[key], exact, child))
    elif isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            failures.append({"path": path, "reason": "different_length", "expected": len(expected), "actual": len(actual)})
        for i, (left, right) in enumerate(zip(expected, actual)):
            failures.extend(compare(left, right, exact, path + f"/{i}"))
    elif type(expected) is not type(actual) or expected != actual:
        failures.append({"path": path, "reason": "different_value", "expected": expected, "actual": actual})
    return failures[:100]
