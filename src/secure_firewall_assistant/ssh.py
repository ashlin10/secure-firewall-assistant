import base64
import hashlib
import re
import socket
import time

import paramiko

from .errors import AssistantError

FTD_COMMANDS = {"show version", "show managers", "show network", "show high-availability"}
DIAGNOSTIC_PATTERNS = [
    r"show version", r"show failover", r"show failover state", r"show route", r"show conn count",
    r"show access-list(?: [A-Za-z0-9_.-]+)?", r"show interface(?: [A-Za-z0-9_.:/-]+)?",
]
PROMPT = re.compile(r"(?m)^[A-Za-z0-9][A-Za-z0-9_.()/ :\-]*[>#]\s*\Z")


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def host_key(device):
    try:
        with socket.create_connection((device.address, device.port), timeout=10) as connection:
            transport = paramiko.Transport(connection)
            try:
                transport.start_client(timeout=10)
                return transport.get_remote_server_key()
            finally:
                transport.close()
    except Exception:
        raise AssistantError("ssh_key_exchange_failed", "Could not obtain the FTD host key. Check local network access.") from None


def save_host_key(state, device, key):
    from .state import private_dir

    private_dir(state.config)
    path = state.config / "known_hosts"
    keys = paramiko.HostKeys()
    if path.exists():
        keys.load(str(path))
    hostname = device.address if device.port == 22 else f"[{device.address}]:{device.port}"
    keys.add(hostname, key.get_name(), key)
    keys.save(str(path))
    if path.exists() and __import__("os").name != "nt":
        path.chmod(0o600)


def validate_commands(commands: list[str], mode: str):
    if mode not in {"ftd", "diagnostic"} or not 1 <= len(commands) <= 10:
        raise AssistantError("invalid_diagnostic_request", "Choose ftd or diagnostic mode and 1–10 supported read-only commands.")
    for command in commands:
        if len(command) > 200 or any(c in command for c in "\r\n;|&`$\\"):
            raise AssistantError("ssh_command_rejected", "Only a single supported read-only diagnostic command is accepted.")
        allowed = command in FTD_COMMANDS if mode == "ftd" else any(re.fullmatch(p, command) for p in DIAGNOSTIC_PATTERNS)
        if not allowed:
            raise AssistantError("ssh_command_rejected", "This command is outside the v1 diagnostic allowlist.", mode=mode)


def receive(channel, timeout=12):
    deadline = time.monotonic() + timeout
    output = ""
    while time.monotonic() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(32768).decode("utf-8", errors="replace")
            output += chunk
            if len(output) > 1024 * 1024:
                raise AssistantError("ssh_output_limit", "Diagnostic output exceeded the bounded capture limit.")
            if re.search(r"(?im)(?:password|passphrase):\s*$", output):
                raise AssistantError("ssh_privilege_required", "This diagnostic context requires separate interactive access; no privilege escalation was attempted.")
            if "<--- More --->" in chunk or "--More--" in chunk:
                channel.send(" ")
            if PROMPT.search(output):
                return output
        elif channel.closed:
            break
        else:
            time.sleep(0.05)
    raise AssistantError("ssh_prompt_timeout", "The FTD prompt was not recognized within the diagnostic timeout.")


def diagnostics(state, secrets, target: str, commands: list[str], mode="ftd") -> dict:
    validate_commands(commands, mode)
    device = state.device(target, "ftd")
    known_hosts = state.config / "known_hosts"
    if not known_hosts.exists():
        raise AssistantError("ssh_trust_required", "Enroll and verify the FTD host key using the local trust-host utility.")
    client = paramiko.SSHClient()
    client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(device.address, port=device.port, username=device.username,
                       password=secrets.get(device.credential_ref), look_for_keys=False, allow_agent=False,
                       timeout=10, auth_timeout=10, banner_timeout=10)
        channel = client.invoke_shell(width=160, height=48)
        receive(channel)
        if mode == "diagnostic":
            channel.send("system support diagnostic-cli\n")
            receive(channel)
        results = []
        for command in commands:
            channel.send(command + "\n")
            results.append({"command": command, "output": receive(channel)})
        return {"target": target, "mode": mode, "commands": results,
                "runtime_observed": True, "configuration_changed": False,
                "note": "Command output is evidence; evaluate it against the requested expectations."}
    except AssistantError:
        raise
    except paramiko.BadHostKeyException:
        raise AssistantError("ssh_host_key_changed", "The FTD host key differs from the enrolled key; investigate locally.") from None
    except paramiko.AuthenticationException:
        raise AssistantError("ssh_authentication_failed", "Check the locally enrolled FTD account.") from None
    except Exception:
        raise AssistantError("ssh_connection_failed", "SSH diagnostics failed. Check access, host-key enrollment, and the FTD CLI context.") from None
    finally:
        client.close()
