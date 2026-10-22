import base64
import hashlib
import re
import socket
import time

import paramiko
from filelock import FileLock

from .errors import AssistantError

FTD_COMMANDS = {"show version", "show managers", "show network", "show high-availability"}
DIAGNOSTIC_PATTERNS = [
    r"show version", r"show failover", r"show failover state", r"show route", r"show conn count",
    r"show access-list(?: [A-Za-z0-9_.-]+)?", r"show interface(?: [A-Za-z0-9_.:/-]+)?",
]
PROMPT = re.compile(r"(?m)^(?:[A-Za-z0-9][A-Za-z0-9_.()/ :\-]*)?[>#]\s*\Z")


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
    with FileLock(str(path) + ".lock"):
        keys = paramiko.HostKeys()
        if path.exists():
            keys.load(str(path))
        hostname = device.address if device.port == 22 else f"[{device.address}]:{device.port}"
        keys.add(hostname, key.get_name(), key)
        keys.save(str(path))
        if path.exists() and __import__("os").name != "nt":
            path.chmod(0o600)


class AcceptDeviceHostKey(paramiko.MissingHostKeyPolicy):
    """Accept and record every presented lab device key without prompting."""

    def __init__(self, state, device):
        self.state = state
        self.device = device

    def missing_host_key(self, client, hostname, key):
        save_host_key(self.state, self.device, key)


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
    client = paramiko.SSHClient()
    # Do not load pinned keys: automatic acceptance also applies to replaced keys.
    client.set_missing_host_key_policy(AcceptDeviceHostKey(state, device))
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
    except paramiko.AuthenticationException:
        raise AssistantError("ssh_authentication_failed", "Check the locally enrolled FTD account.") from None
    except Exception:
        raise AssistantError("ssh_connection_failed", "SSH diagnostics failed. Check access and the FTD CLI context.") from None
    finally:
        client.close()


CLI_TOKEN = re.compile(r"[A-Za-z0-9_.:/,@%+=-]+")
CLI_ERROR = re.compile(r"(?im)^\s*(?:%\s*)?(?:error\b|invalid\b|unknown command\b|syntax error\b|failed\b)")


def configuration(state, secrets, target: str, authorization_request: str,
                  commands: list[list[str | dict]], verification_commands: list[str]) -> dict:
    """Run FTD configure commands, with no shell or automatic replay after failures."""
    if not authorization_request.strip():
        raise AssistantError("authorization_required", "Supply the current user's configuration request.")
    if not 1 <= len(commands) <= 10:
        raise AssistantError("invalid_configuration_request", "Supply 1–10 FTD configure commands as token arrays.")
    validate_commands(verification_commands, "ftd")
    device = state.device(target, "ftd")
    prepared = []
    for tokens in commands:
        if not isinstance(tokens, list) or len(tokens) < 2 or tokens[0] != "configure":
            raise AssistantError("ssh_command_rejected", "Use FTD configure commands; FMC changes require HTTPS REST.")
        # Registration keys and explicitly named credential arguments stay local.
        for index, token in enumerate(tokens):
            secret_argument = (tokens[:3] == ["configure", "manager", "add"] and index == 4)
            secret_argument |= index > 0 and isinstance(tokens[index - 1], str) and tokens[index - 1].lower() in {
                "password", "secret", "key", "community"}
            if secret_argument and not (isinstance(token, dict) and set(token) == {"$secret"}):
                raise AssistantError("literal_secret_rejected", "Use a local $secret reference for CLI credentials.")
        resolved = [secrets.resolve(token) if isinstance(token, dict) else token for token in tokens]
        if any(not isinstance(token, str) or not CLI_TOKEN.fullmatch(token) for token in resolved):
            raise AssistantError("ssh_command_rejected", "CLI tokens cannot contain whitespace, control characters, or shell operators.")
        command = " ".join(resolved)
        if len(command) > 1000:
            raise AssistantError("ssh_command_rejected", "The FTD configure command exceeds the length limit.")
        prepared.append(command)
    result = {"target": target, "commands": [], "verification_commands": [],
              "configuration_attempted": False, "configuration_may_have_changed": False,
              "verification_status": "not_observed", "ok": False,
              "note": "CLI responses and read-back are evidence; compare them with the requested outcome. Never replay uncertain writes."}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(AcceptDeviceHostKey(state, device))
    try:
        with state.target_lock(target):
            client.connect(device.address, port=device.port, username=device.username,
                           password=secrets.get(device.credential_ref), look_for_keys=False, allow_agent=False,
                           timeout=10, auth_timeout=10, banner_timeout=10)
            channel = client.invoke_shell(width=160, height=48)
            receive(channel)
            for command in prepared:
                result["configuration_attempted"] = True
                result["configuration_may_have_changed"] = True
                result["commands"].append({"command": command, "status": "outcome_unknown"})
                channel.send(command + "\n")
                output = receive(channel, timeout=60)
                result["commands"][-1].update(output=output, status="response_received")
                if CLI_ERROR.search(output):
                    raise AssistantError("ftd_cli_error", "FTD rejected a command. Reconcile observed state before continuing.")
            for command in verification_commands:
                channel.send(command + "\n")
                output = receive(channel)
                result["verification_commands"].append({"command": command, "output": output})
                if CLI_ERROR.search(output):
                    raise AssistantError("ftd_verification_error", "FTD rejected a verification command.")
            result.update(ok=True, verification_status="observed")
    except AssistantError as error:
        result["error"] = error.result()["error"]
    except paramiko.AuthenticationException:
        result["error"] = {"code": "ssh_authentication_failed", "message": "Check the locally enrolled FTD account."}
    except Exception:
        result["error"] = {"code": "ssh_configuration_failed", "message": "FTD SSH failed; reconcile any attempted changes before retrying."}
    finally:
        client.close()
    return secrets.redactor.clean(result)
