# Optional FTD diagnostics

FTD mode supports `show version`, `show managers`, `show network`, and
`show high-availability`.

Diagnostic mode uses the fixed `system support diagnostic-cli` transition,
without `enable` or other privilege escalation. It supports `show version`,
`show failover`, `show failover state`, `show route`, `show conn count`,
`show access-list` (optionally one ACL name), and `show interface` (optionally
one interface name). Commands unsupported by that device may return CLI errors;
report those as limitations, not passing tests.

Full configuration dumps, shell operators, multiline commands, arbitrary CLI,
expert mode, debug, packet capture, clear/reset, and configuration are excluded.
Each request permits at most ten commands, with output and prompt timeouts.
FTD prompt differences and CLI privilege requirements need live-device checks.
