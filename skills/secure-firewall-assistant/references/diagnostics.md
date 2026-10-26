# FTD SSH configuration and diagnostics

FTD mode supports `show version`, `show managers`, `show network`, and
`show high-availability`.

Diagnostic mode uses the fixed `system support diagnostic-cli` transition,
without `enable` or other privilege escalation. It supports `show version`,
`show failover`, `show failover state`, `show route`, `show conn count`,
`show access-list` (optionally one ACL name), and `show interface` (optionally
one interface name). Commands unsupported by that device may return CLI errors;
report those as limitations, not passing tests.

The diagnostics tool excludes configuration writes, full configuration dumps,
shell operators, multiline commands, expert mode, debug, packet capture, and clear/reset.
Each request permits at most ten commands, with output and prompt timeouts.
FTD prompt differences and CLI privilege requirements need live-device checks.

## Configuration

FMC writes use HTTPS REST APIs. For FTD writes use `ftd_configuration` with the
exact enrolled FTD alias, a faithful `authorization_request`, 1–10 token arrays
beginning with `configure`, and `verification_commands` from the FTD read-only
allowlist. For example, manager registration uses:

```json
{
  "target": "lab-ftd",
  "authorization_request": "Register lab-ftd to lab-fmc",
  "commands": [["configure", "manager", "add", "192.0.2.10", {"$secret": "lab-registration"}]],
  "verification_commands": ["show managers", "show network"]
}
```

Secret values are resolved locally and redacted from command echoes and evidence.
When a key is unspecified, use `prepare_registration_key` with the enrolled FMC
and FTD aliases plus the current registration request. Use the returned reference
in both SSH and FMC registration; the random key never leaves local storage.
The tool reuses an existing key for the pair rather than rotating it on retries. Do not use a login password
as a registration key. Each argument must be a single CLI token. Shell operators,
control characters, expert mode, and privilege escalation are not supported.
Commands requiring interactive confirmation are not auto-confirmed: a timeout
stops the sequence and leaves the outcome unknown. Commands are never retried.

Inspect `configuration_attempted`, `configuration_may_have_changed`, per-command
receipts, errors, and verification output. A returned prompt is only a CLI receipt;
compare read-back with the intended state and observe async FMC registration
separately. Failures preserve partial receipts in evidence. Reconcile before
continuing. Configuration can affect runtime immediately; deployment remains a
separate explicit request.

## General device SSH (0.6.0)

`device_ssh` accepts every enrolled category without a command allowlist. Use
`authorization_request` and `commands` (1–100 strings, up to 64 KiB each), with
`mode: shell` (default, one retained interactive context) or `mode: exec` (one
SSH exec channel per command, reporting stdout/stderr/exit status).
`timeout_seconds` is 1–300 per command; output is bounded to 1 MiB per command.
These are transport limits, not restrictions on command content. Pipe operators,
multiline input, OS commands and CLI configuration contexts are accepted.

Optional `prompt_pattern` matches the end-of-output prompt. Interactive replies
are explicit objects such as `{ "pattern": "Destination filename.*\\?\\s*$",
"response": "" }`; password replies use `{"$secret":"local-reference"}` as
`response`. Nothing automatically sends an enable/sudo password. Commands can
use `{"template":"command {{key}}", "values":{"key":{"$secret":"local-key"}}}`.
Resolved local secrets are redacted from receipts and output. Avoid literal
secrets. Shell commands default to stopping on recognized CLI errors; exec mode
uses the exit status. `stop_on_error: false` allows continued execution after a
reported command error; transport loss/timeouts always stop. No command is
replayed. Review output and explicitly read back changes: command completion
alone does not prove the requested state or startup persistence.

For console-server connections, explicitly respond to the console login prompts
using `{"$device":"ssh_username"}` or `{"$device":"ssh_password"}` as the
response value. These resolve only the selected device’s enrolled SSH account
locally; no password is returned to the model. A `Password OK` console-server
prompt can receive an explicit empty response to solicit the device login.

When the SSH endpoint is a console server and the downstream device uses the
other enrolled account, explicit `{"$device":"https_username"}` and
`{"$device":"https_password"}` responses select that account for the console
login. SSH transport still uses the enrolled SSH account. Do not assume that a
transport login and downstream console login use the same account.
