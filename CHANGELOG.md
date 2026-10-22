# 0.5.3 — 2026-10-22

- Assume sensible defaults for unspecified configuration details and create a
  default access policy for device registration when needed.
- Generate and reuse registration keys locally for exact FMC/FTD pairs without
  exposing values or reusing device login passwords.
- Recognize FMC empty collections that omit items while reporting zero count.

# 0.5.2 — 2026-10-22

- Configure FMC through HTTPS REST and FTD through a dedicated SSH configuration
  tool; keep diagnostics read-only.
- Resolve CLI secret references locally, record partial outcomes without replay,
  and collect read-only verification after FTD changes.
- Clarify device registration using observed management IPs and matching local
  registration keys.


# 0.5.1 — 2026-10-22

- Enable the documented single/bulk device registration collection API in the configuration executor.
- Automatically accept and record device SSH host keys, including changed keys, without a permission prompt.

# Inventory layout update — 2026-10-22

- Save all six device types as lists beneath `devices`, with the type supplied by the section. Read legacy formats and preserve accounts during migration.

# 0.5.0 — 2026-10-22

- Bootstrap from the installed plugin root and prepare locked runtimes automatically on startup after a package update.
- Add a stable standalone MCP dispatcher that resolves the installed plugin through Codex and activates its prepared runtime.
- Migrate legacy standalone MCP transport fields automatically, preserving other configuration and saving a local backup.
- Serialize preparation, verify health before activation, reuse ready runtimes offline, and retain the previous selection after failed preparation.
- Report the actual package version in assistant health.

# 0.4.1 — 2026-10-22

- Open enrollment in a dedicated form that never returns existing inventory and only adds new devices.
- Reject enrollment name collisions and deletions before writing, including concurrent saves.
- Restrict the schema registry POSIX permission assertion to platforms that support it.
- Snapshot deployed schema service source, installed unit, and complete registry history to a separate Cisco repository during the release push workflow.

# 0.4.0 — 2026-10-22

- Add a shared read-only HTTP MCP schema service with administrative version/revision publishing.
- Identify the supplied schema as FMC 10.5.0.0 and select the latest published version for missing versions.
- Fetch and cache schemas locally, pin validation through execution and verification, and record selection/fallback evidence.
- Group device YAML into six categories and add the device-type dropdown with credential-preserving migration.

# Changelog


## 0.3.9

- Correct the VPN endpoint create schema to declare `bulk=true` and array bodies; preserve the correction during schema imports.

## 0.3.8

- Expose execution options for all REST methods, including bulk, array bodies, filtering, pagination, media types, and async responses; add bulk-only discovery.
- Add independent-create batch execution that selects declared native bulk, otherwise uses up to four concurrent supported POSTs, with one compatibility check and complete collection verification.
- Validate the full batch before writing; stop scheduling on errors or async acceptance, retain per-item receipts, and never replay uncertain writes.
- Require capability inspection before large jobs and reconciliation of partial outcomes within the original parent resource.

## 0.3.7

- Accept self-signed HTTPS certificates and hostname mismatches by default for lab FMCs, including existing inventory.
- Retain strict certificate verification through per-device `verify_ssl`, `--verify-ssl`, or an enrolled CA bundle.
- Report the effective TLS verification mode on connection and test real self-signed TLS connections.

## 0.3.6

- Add per-device username and password fields to the inventory form and store clear text passwords under each device in local YAML.
- Migrate legacy login credentials into device records, retaining API secret references and creating a private migration backup.
- Add accessible trash buttons; save explicit deletions, including legacy inventory entries, and allow an empty inventory.
- Preserve saved passwords when fields are blank, retain password whitespace, and keep saved passwords out of tool results.
- Restrict the password-saving MCP tool to app visibility.

## 0.3.5

- Replace credential enrollment with a device inventory form containing Device Name, Hostname/IP Address, HTTPS port, and SSH port for each device.
- Save validated inventory rows atomically to local devices.yaml, preserving existing credentials and advanced settings.
- Remove the local connection check, password fields, loopback listener, and automatic FMC connection from the form.
- Add device_inventory and save_device_inventory tools; retain start_enrollment as an inventory compatibility entrypoint.


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
