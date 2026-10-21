# Project working instructions

- A clear user request authorizes ordinary in-scope implementation, validation,
  local installation, commits, and pushes without repeated confirmation.
- Whenever this project changes, complete the release workflow before reporting
  completion: run appropriate checks, install the current source with
  `scripts/install.py`, refresh the local plugin, and update the standalone
  `secure-firewall` MCP registration to the exact release directory returned by
  the installer. Never leave MCP pinned to an older release.
- Verify the registered server's tools and relevant MCP App resource through
  stdio. Distinguish that verification from rendering in the current desktop
  session; report when a host restart is still required.
- Commit all intended project changes and push them to BOTH configured remotes,
  `origin` (Cisco GitHub Enterprise) and `github` (GitHub), using
  `scripts/push_repositories.py` on main. Verify both remote branch tips match
  the local commit. Do this routinely without waiting for the user to remind you.
- Never commit credentials, private inventory, evidence, local release paths, or
  machine-specific MCP registration. Preserve unrelated work and remote history;
  do not force-push. Report any installation or push failure explicitly.
- An explicit user request to keep work local, uncommitted, or unpushed overrides
  this default workflow for that request.
