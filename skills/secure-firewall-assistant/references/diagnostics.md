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
