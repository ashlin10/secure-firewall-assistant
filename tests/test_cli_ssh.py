import json

import pytest

from secure_firewall_assistant import cli
from secure_firewall_assistant.errors import AssistantError
from secure_firewall_assistant.ssh import receive


def test_hidden_entry_requires_terminal_and_matching_values(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    with pytest.raises(AssistantError) as error:
        cli.hidden_password()
    assert error.value.code == "interactive_enrollment_required"
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    values = iter(["SYNTHETIC-ONE", "SYNTHETIC-TWO"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda label: next(values))
    with pytest.raises(AssistantError) as error:
        cli.hidden_password()
    assert error.value.code == "password_mismatch"


def test_cli_has_no_password_argument():
    with pytest.raises(SystemExit):
        cli.parser().parse_args(["enroll", "fmc", "alias", "https://fmc.example.invalid", "--username", "user", "--password", "SYNTHETIC"])


def test_cli_health_and_device_listing_are_offline(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SFA_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(cli.sys, "argv", ["secure-firewall-assistant", "health"])
    cli.main()
    assert json.loads(capsys.readouterr().out)["network_access_tested"] is False
    monkeypatch.setattr(cli.sys, "argv", ["secure-firewall-assistant", "list"])
    cli.main()
    assert json.loads(capsys.readouterr().out) == {"devices": []}


class Channel:
    def __init__(self, parts):
        self.parts = list(parts)
        self.sent = []
        self.closed = False

    def recv_ready(self):
        return bool(self.parts)

    def recv(self, _):
        return self.parts.pop(0)

    def send(self, value):
        self.sent.append(value)


def test_ssh_prompt_and_pagination():
    channel = Channel([b"show interface\r\noutput\r\n<--- More --->", b"\r\nmore output\r\nfirepower# "])
    assert "more output" in receive(channel)
    assert channel.sent == [" "]


def test_ssh_never_sends_an_enable_password():
    channel = Channel([b"Password: "])
    with pytest.raises(AssistantError) as error:
        receive(channel)
    assert error.value.code == "ssh_privilege_required"
    assert channel.sent == []


def test_empty_expectations_cannot_create_vacuous_success(assistant, lab):
    with pytest.raises(AssistantError) as error:
        assistant.verify("lab-fmc-1", "getAllNetworkObject", {})
    assert error.value.code == "expectations_required"
    assert not lab.calls


def test_evidence_pointer_and_secret_echo_redaction(assistant):
    assistant.secrets.redactor = assistant.redactor
    assistant.secrets.set("fixture-ref", "SYNTHETIC-SECRET-SENTINEL")
    saved = assistant.evidence.save({"result": {"body": {"echo": assistant.secrets.get("fixture-ref")}}, "ok": True})
    selected = assistant.evidence.read(saved["run_id"], pointer="/result/body/echo")
    assert selected["value"] == "[REDACTED]"
    assert "SYNTHETIC" not in (assistant.evidence.directory / (saved["run_id"] + ".json")).read_text()
    with pytest.raises(AssistantError):
        assistant.evidence.read(saved["run_id"], pointer="/missing")
