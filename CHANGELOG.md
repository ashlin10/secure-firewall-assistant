## 0.6.11

- Preserve JSON Schema primitive types when sanitizing sample credentials so boolean request parameters remain valid.
- Republish affected 7.0, 7.6, and 7.7 families as r2, preserving immutable prior revisions.

## 0.6.10

- Add release-family schema selection: exact versions win, patch/build versions use their major/minor baseline, and unpublished families report latest fallback.
- Support staged, version-specific schema imports and faithful Swagger 2.0 conversion for FMC 7.0 without applying 10.5-specific corrections.
- Publish sanitized schemas for FMC 7.0, 7.1, 7.2, 7.3, 7.4, 7.6, 7.7, 10.0, and 10.1 as r1 while preserving 10.5 r2 and immutable schema history.

## 0.6.9

- Keep only current plugin/source ZIPs after a successful package build.
- Add verified active-release cleanup for old runtimes and plugin caches, with running-process and identity checks. Preserve private data and schema revision history.
- Require latest-only release cleanup in the project workflow.

## 0.6.8

- Restore the shared schema MCP endpoint http://10.196.150.41:8765/mcp as the default in exported plugins, with no recipient configuration required.
- Fetch schemas remotely and check revisions at most once per minute during use; retain validated cached schemas during outages and fail without a cache. Never silently use the bundled snapshot for production operations.
- Keep local URL overrides and portable packaging; reject empty URLs instead of disabling remote updates.

## 0.6.7

- Make the recipient ZIP independent of personal paths and private schema infrastructure; use the bundled FMC schema by default with an optional locally configured shared service.
- Exclude maintainer deployment/synchronization scripts and local runtime artifacts from the plugin ZIP; reject machine-specific home paths during packaging.
- Document export/import and per-recipient setup without sharing inventory, credentials, caches, or virtual environments.

## 0.6.6

- Scope standalone MCP plugin discovery to its enabled marketplace so unrelated marketplace lookups cannot block startup. Preserve duplicate-plugin checks.

## 0.6.5

- Compare deployment preview content independently of FMC’s per-read deployment timestamp, and submit the latest timestamp after revalidation.

## 0.6.4

- Project RA VPN create requests separately from generated child references and optional DAP response fields.

## 0.6.3

- Support certificate enrollment and policy assignment configuration through REST.
- Preserve VPN control flags and password format selectors during redaction and validation.

## 0.6.2

- Recognize FTD HA pair configuration endpoints in the ordinary REST executor, including creation, updates, and interface settings.

# 0.6.1 — 2026-10-26

- Allow explicit selected-device HTTPS account references in SSH prompt responses, so console-server SSH authentication can use one enrolled account and downstream device login can use the other without exposing credentials or changing transport authentication.

# 0.6.0 — 2026-10-26

- Add general read/write/execute SSH access to every enrolled category without a command allowlist.
- Support interactive CLI context, SSH exec status/stderr, custom prompts, explicit interactive responses, and local secret templates with redacted partial evidence and no replay.
- Select the enrolled SSH account independently of HTTPS for FMC SSH.
- Use the Paramiko 4 compatibility line for older lab switch SHA-1 key exchange and RSA signatures, retaining stronger algorithms first.

# 0.5.5 — 2026-10-26

- Accept the FMC route-based VPN endpoint interface type `VTI` in single/bulk REST creates, updates, and read-back validation. Preserve physical-interface and tunnel-source constraints.
- Preserve the correction during schema imports and publish it as FMC 10.5.0.0 schema revision r2.

# 0.5.4

- Store and edit separate SSH and HTTPS accounts per device, with shared-account migration.
- Select protocol credentials for FMC REST and FTD SSH while preserving inventory-only saves.

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
