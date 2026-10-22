import json
from dataclasses import replace

import pytest

from secure_firewall_assistant.errors import AssistantError
from secure_firewall_assistant.security import Redactor
from secure_firewall_assistant.ssh import validate_commands
from secure_firewall_assistant.state import Device


def test_local_secret_references_resolve_without_literal_values(assistant):
    assistant.secrets.set("radius-fixture", "SYNTHETIC-RADIUS-SENTINEL")
    resolved = assistant.secrets.resolve({"serverSecretKey": {"$secret": "radius-fixture"}})
    assert resolved["serverSecretKey"] == "SYNTHETIC-RADIUS-SENTINEL"
    with pytest.raises(AssistantError) as error:
        assistant.secrets.resolve({"password": "SYNTHETIC-LITERAL-SENTINEL"})
    assert error.value.code == "literal_secret_rejected"
    assert "SYNTHETIC-LITERAL" not in json.dumps(error.value.result())
    assert assistant.secrets.resolve({"defaultPasswordAlreadyChanged": True}) == {"defaultPasswordAlreadyChanged": True}


def test_redaction_handles_tokens_nested_metadata_and_pem():
    redactor = Redactor()
    redactor.register("SYNTHETIC-KNOWN-SENTINEL")
    value = {"password": "unregistered", "details": {"field": "password", "value": "unregistered"},
             "message": "echo SYNTHETIC-KNOWN-SENTINEL", "pem": "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-KEY\n-----END PRIVATE KEY-----"}
    output = json.dumps(redactor.clean(value))
    assert "unregistered" not in output and "SYNTHETIC" not in output
    assert redactor.clean({"code": "literal_secret_rejected"})["code"] == "literal_secret_rejected"


def test_registration_key_does_not_replace_login_or_existing_key(assistant):
    assistant.secrets.set("lab-fmc-1-auth", "SYNTHETIC-LOGIN-SENTINEL",
                          device=assistant.state.device("lab-fmc-1"))
    with pytest.raises(AssistantError) as error:
        assistant.secrets.ensure_registration_key("lab-fmc-1-auth")
    assert error.value.code == "registration_reference_conflict"
    assert assistant.secrets.get("lab-fmc-1-auth") == "SYNTHETIC-LOGIN-SENTINEL"
    assistant.secrets.set("registration-fixture", "SYNTHETIC-REGISTRATION-SENTINEL")
    assert assistant.secrets.ensure_registration_key("registration-fixture") is False
    assert assistant.secrets.get("registration-fixture") == "SYNTHETIC-REGISTRATION-SENTINEL"


@pytest.mark.parametrize("command", ["configure terminal", "expert", "show version; reboot", "show version\nreboot",
                                      "show version | include x", "show running-config", "enable", "show $(id)"])
def test_ssh_commands_cannot_mutate_or_escape(command):
    with pytest.raises(AssistantError):
        validate_commands([command], "diagnostic")


def test_allowlisted_diagnostics_and_bounds():
    validate_commands(["show version", "show network"], "ftd")
    validate_commands(["show access-list ACL-1", "show interface GigabitEthernet0/1"], "diagnostic")
    with pytest.raises(AssistantError):
        validate_commands(["show version"] * 11, "ftd")


@pytest.mark.parametrize("address", ["http://fmc.example.invalid", "https://user:sentinel@fmc.example.invalid", "https://fmc.example.invalid/path", "https://fmc.example.invalid?token=x"])
def test_inventory_requires_https_origin_without_embedded_credentials(address):
    with pytest.raises(AssistantError):
        Device("lab-fmc-1", "fmc", address, "user", "ref")


def test_inventory_upgrade_backup_preserves_original(state):
    original = state.inventory_path.read_bytes()
    state.save_device(replace(state.device("lab-fmc-1"), domain="NewDomain"))
    assert json.loads(original) == json.loads((state.config / "inventory.backup.json").read_text())
    assert state.device("lab-fmc-1").domain == "NewDomain"


def test_evidence_rejects_path_traversal(assistant):
    with pytest.raises(AssistantError):
        assistant.evidence.read("../../inventory.json")
