# Changelog

## 0.3.4

- Save local device details and credentials in an ignored `devices.yaml` beside the plugin; keep only a credential-free example in source packages.
- Use the embedded ChatGPT enrollment form to enter device details and credentials.
- Write the YAML atomically with restrictive Unix file permissions.

## 0.3.3

- Check local loopback access before showing password fields, with a short-lived authenticated probe.
- Explain when the embedding app host blocks loopback access so users know no password was sent.

## 0.3.2

- Make enrollment text readable in light/dark themes and remove domain/CA controls from the card.
- Bound save requests, confirm saved status, check FMC connectivity separately, and support checking after a lost response.
- Keep status reads responsive while native credential-store prompts are open.
- Consume rejected enrollment request bodies to prevent Windows connection resets.
- Use managed Python in CI, allow slower cold stdio startup, and retain failed test reports for both platforms.

## 0.3.1

- Include Codex compatibility manifests and keep both MCP launch files aligned during installation.
- Document explicit local MCP registration for desktop installations that load skills without the bundled server.


## 0.3.0

- Replaced browser enrollment with an embedded MCP App card and plugin UI entrypoint.
- Passwords travel directly to a one-use, origin-restricted loopback endpoint; never through MCP calls, model context, or widget state.
- Hosts without embedded UI/local-network support fail closed without opening a browser.


## 0.2.0

- Start device enrollment from chat using a short-lived loopback form. Passwords go directly to the native credential store, outside model/tool input.
- Added enrollment status tool; existing inventories and credentials are preserved.


## 0.1.0

- Desktop-only portable plugin and reusable skill for macOS/Windows local Work.
- Schema discovery, JSON validation, guarded configuration, read-back, and evidence.
- Native credential storage with local hidden enrollment and secret references.
- Separate explicit full-pending deployment with fresh single-use previews.
- Optional allowlisted FTD SSH diagnostics with enrolled host keys.
- Per-user installation/update/rollback scripts and a controlled release workflow.
- Synthetic-device, credential, installer, and real stdio protocol tests.

Live devices, actual Work import, Windows native execution, and native store
enrollment remain environment-dependent validation steps.
