"""General user-authorized SSH execution for every enrolled device category.

Command contents are deliberately not allowlisted. Transport limits, local credential
resolution, output redaction, target locking and no automatic replay still apply.
"""
import re
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import paramiko

from .errors import AssistantError
from .ssh import CLI_ERROR, AcceptDeviceHostKey

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
DEFAULT_PROMPT = r"(?m)^[^\r\n]*[>#$%]\s*\Z"
LIMIT = 1024 * 1024


def resolve_text(value, secrets, device=None):
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        raise AssistantError("invalid_ssh_text", "Supply command text or a template with local secret references.")
    if set(value) == {"$device"} and device is not None:
        if value["$device"] == "ssh_username":
            return device.username
        if value["$device"] == "ssh_password":
            return secrets.get(device.credential_ref, protocol="ssh")
        raise AssistantError("invalid_ssh_text", "Device references support ssh_username or ssh_password.")
    if set(value) == {"$secret"}:
        return secrets.resolve(value)
    if set(value) != {"template", "values"} or not isinstance(value["template"], str) or not isinstance(value["values"], dict):
        raise AssistantError("invalid_ssh_text", "Use {template: text, values: {name: {$secret: reference}}}.")
    text = value["template"]
    for name, reference in value["values"].items():
        if not isinstance(name, str) or not isinstance(reference, dict) or set(reference) != {"$secret"}:
            raise AssistantError("invalid_ssh_text", "Template values must be local $secret references.")
        marker = "{{" + name + "}}"
        if marker not in text:
            raise AssistantError("invalid_ssh_text", "A named secret marker is absent from the command template.")
        text = text.replace(marker, secrets.resolve(reference))
    return text


def shell_read(channel, prompt, replies, timeout, authenticating=False):
    output, consumed, pages = "", set(), 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if channel.recv_ready():
            output += channel.recv(32768).decode("utf-8", errors="replace")
            if len(output) > LIMIT:
                raise AssistantError("ssh_output_limit", "SSH output exceeded the capture limit; no command will be retried.", output=ANSI.sub("", output[:LIMIT]))
            clean = ANSI.sub("", output).replace("\r", "")
            if authenticating and re.search(r"(?im)^\s*(?:Login incorrect|Authentication failed|Access denied)\s*$", clean):
                raise AssistantError("ssh_console_authentication_failed", "The downstream console rejected the enrolled SSH account; update that device’s account locally before retrying.", output=clean)
            handled = False
            for index, (pattern, response) in enumerate(replies):
                match = pattern.search(clean)
                identity = (index, match.start()) if match else None
                if match and not clean[match.end():].strip():
                    if identity not in consumed:
                        consumed.add(identity)
                        channel.sendall(response + "\n")
                    # ANSI-only/whitespace chunks can leave the already-answered
                    # prompt visible while the server processes the response.
                    handled = True
                    break
            if handled:
                continue
            if re.search(r"(?i)(?:password|passphrase):\s*\Z", clean):
                raise AssistantError("ssh_response_required", "An interactive response is needed. Supply an explicit prompt response using a local secret reference.", output=clean)
            if re.search(r"(?:--\s*More\s*--|<--- More --->)\s*$", clean, re.I):
                pages += 1
                if pages > 1000:
                    raise AssistantError("ssh_output_limit", "SSH pagination limit reached.", output=clean)
                channel.sendall(" ")
            elif prompt.search(clean):
                # Avoid treating a chunk boundary in command output as a prompt.
                time.sleep(0.1)
                if not channel.recv_ready():
                    return clean
        elif channel.closed:
            raise AssistantError("ssh_channel_closed", "SSH channel closed before a prompt; reconcile the command outcome.", output=ANSI.sub("", output))
        else:
            time.sleep(0.03)
    raise AssistantError("ssh_prompt_timeout", "SSH command did not return a recognized prompt before timeout; no replay attempted.", output=ANSI.sub("", output))


def exec_read(channel, timeout):
    output, errors = "", ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if channel.recv_ready():
            output += channel.recv(32768).decode("utf-8", errors="replace")
        if channel.recv_stderr_ready():
            errors += channel.recv_stderr(32768).decode("utf-8", errors="replace")
        if len(output) + len(errors) > LIMIT:
            raise AssistantError("ssh_output_limit", "SSH exec output exceeded the capture limit.", output=output[:LIMIT], stderr=errors[:LIMIT])
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            return output, errors, channel.recv_exit_status()
        time.sleep(0.03)
    raise AssistantError("ssh_exec_timeout", "SSH exec timed out; reconcile any attempted changes before retrying.", output=output, stderr=errors)


def execute(state, secrets, target, authorization_request, commands, mode="shell", timeout_seconds=30,
            prompt_pattern=None, prompt_responses=None, stop_on_error=True):
    if not isinstance(authorization_request, str) or not authorization_request.strip():
        raise AssistantError("authorization_required", "Supply the current user's SSH request.")
    if (not isinstance(commands, list) or not 1 <= len(commands) <= 100 or mode not in {"shell", "exec"} or
            type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300 or type(stop_on_error) is not bool):
        raise AssistantError("invalid_device_ssh_request", "Use 1–100 commands, shell/exec mode, and a 1–300 second per-command timeout.")
    device = state.device(target, protocol="ssh")
    try:
        prompt = re.compile(prompt_pattern or DEFAULT_PROMPT)
        responses = prompt_responses or []
        if not isinstance(responses, list) or len(responses) > 20:
            raise ValueError
        replies = []
        for item in responses:
            if set(item) != {"pattern", "response"} or not isinstance(item["pattern"], str):
                raise ValueError
            replies.append((re.compile(item["pattern"]), resolve_text(item["response"], secrets, device)))
    except (ValueError, TypeError, re.error):
        raise AssistantError("invalid_ssh_prompt", "Supply valid prompt regexes and explicit pattern/response objects.") from None
    prepared = [resolve_text(command, secrets, device) for command in commands]
    if any(not command.strip() or len(command) > 65536 or "\x00" in command for command in prepared):
        raise AssistantError("invalid_ssh_text", "SSH command text must be nonempty, NUL-free and at most 64 KiB.")
    address = urlsplit(device.address).hostname if device.kind == "fmc" else device.address
    result = {"ok": False, "target": target, "device_type": device.kind, "mode": mode, "commands": [],
              "execution_attempted": False, "configuration_may_have_changed": False,
              "verification_status": "requires_command_output_review", "automatic_retries": 0}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(AcceptDeviceHostKey(state, SimpleNamespace(address=address, port=device.port)))
    channel = None
    try:
        with state.target_lock(target):
            client.connect(address, port=device.port, username=device.username,
                           password=secrets.get(device.credential_ref, protocol="ssh"),
                           look_for_keys=False, allow_agent=False, timeout=10, auth_timeout=10, banner_timeout=10)
            if mode == "shell":
                channel = client.invoke_shell(width=240, height=100)
                result["initial_output"] = shell_read(channel, prompt, replies, timeout_seconds, True)
            for index, command in enumerate(prepared):
                receipt = {"index": index, "command": command, "status": "outcome_unknown"}
                result["commands"].append(receipt)
                result.update(execution_attempted=True, configuration_may_have_changed=True)
                if mode == "shell":
                    channel.sendall(command + ("" if command.endswith("\n") else "\n"))
                    output = shell_read(channel, prompt, replies, timeout_seconds)
                    receipt.update(output=output, status="response_received")
                    failed = bool(CLI_ERROR.search(output) or re.search(r"(?im)^\s*%.*(?:denied|incomplete|ambiguous|not authorized)", output))
                else:
                    channel = client.get_transport().open_session(timeout=10)
                    try:
                        channel.exec_command(command)
                        output, stderr, status = exec_read(channel, timeout_seconds)
                        receipt.update(output=output, stderr=stderr, exit_status=status, status="response_received")
                        failed = status != 0
                    finally:
                        channel.close()
                        channel = None
                if failed:
                    receipt["status"] = "command_failed"
                    if stop_on_error:
                        raise AssistantError("device_ssh_command_failed", "Command returned an error; later commands were not attempted. Reconcile state before retrying.")
            result["ok"] = all(c["status"] == "response_received" for c in result["commands"])
    except AssistantError as error:
        result["error"] = error.result()["error"]
    except paramiko.AuthenticationException:
        result["error"] = {"code": "ssh_authentication_failed", "message": "Check the enrolled device's SSH account."}
    except Exception as error:
        result["error"] = {"code": "device_ssh_failed", "message": "SSH failed; reconcile any attempted commands before retrying.",
                           "exception_type": type(error).__name__, "detail": str(error)[:2000]}
    finally:
        if channel is not None:
            channel.close()
        client.close()
    return secrets.redactor.clean(result)
