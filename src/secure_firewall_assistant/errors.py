from typing import Any


class AssistantError(Exception):
    """Only deliberately safe text and structured details may cross the tool boundary."""

    def __init__(self, code: str, message: str, **details: Any):
        self.code = code
        self.message = message
        self.details = details
        super().__init__(message)

    def result(self) -> dict:
        return {"ok": False, "error": {"code": self.code, "message": self.message, **self.details}}
