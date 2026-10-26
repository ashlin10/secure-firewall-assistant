## 0.6.1 console account selection

- Full suite: 200 tests passed, including separate SSH transport and downstream console-account selection without model-visible credentials.
- Live console-server SSH authentication and downstream switch login succeeded with the two respective enrolled accounts; no inventory credential change was required.
- Regression tests confirm selecting the downstream account does not replace the transport SSH account or expose either password in results.

## 0.6.0 general device SSH

- General SSH tests cover all six enrolled categories, arbitrary pipe/multiline command text, retained CLI context, SSH exec exit status/stderr, protocol-specific FMC SSH accounts, local secret templates, explicit console credentials, network/OS prompts, paging, partial evidence, and no automatic command replay.
- Regression coverage prevents re-sending an interactive response on ANSI/whitespace chunks or mistaking an earlier password prompt for a new prompt after authentication.
- Downstream console authentication failure stops before another credential reply. Live switch connections negotiated legacy SSH successfully; the console login rejected the enrolled account, so no switch configuration was attempted.
- Standalone stdio verification checks the installed release, write/execute tool annotation, all 20 tools, and both inventory MCP App resources. Desktop tool refresh is a separate host-restart check.

# 0.5.3 validation — 2026-10-22

- 173 automated tests pass, including concurrent local registration key creation,
  pair isolation, key reuse without exposing values or replacing login accounts,
  and zero-count FMC responses without items. Malformed responses still fail.
- Ruff and whitespace checks pass. The release retains explicit deployment guards
  and uses observed management IPs for registration.
- Verify installed stdio tools and MCP App resources separately from rendering in
  an existing desktop chat; the host must reload to see new tool definitions.

# 0.4.0 validation — 2026-10-22

- 118 automated tests cover existing REST/deployment guards, remote schema selection, revision immutability, cache outages/corruption, and typed YAML migration.
- Live shared HTTP MCP on the authorized host: six read-only tools, health check, exact 10.5.0.0 selection, and latest-version fallback for 10.1.0.
- Live local stdio: 17 tools, inventory MCP App HTML resource containing all six device types, four enrolled FMC aliases, and read-only FMCv-102 topology enumeration using remote schema 10.5.0.0 r1.
- Existing account values and API-only secrets were compared in memory before/after migration; backups and owner-only YAML permissions were preserved. No credential values were logged.
- MCP App resource/bridge behavior is verified separately from desktop rendering. A host restart/new session is required to replace tools already loaded in an active chat.
- This release does not claim runtime VPN testing, FTD deployment, or new execution adapters for the four extra inventory categories.

# Validation report — 21 October 2026

## 0.3.8 capability discovery and efficient batches

- 108 automated tests cover the existing suite plus native bulk selection, all-method capability discovery, full-batch preflight, real bounded non-bulk concurrency, one collection verification, mismatches, async acceptance, and failure receipts without write replay.
- Ruff and reproducible plugin/source packaging pass. The maintained OpenAPI snapshot is unchanged; no undocumented VPN endpoint bulk parameter was added.
- Batch creates retain target locking, secret-reference resolution, ordinary-configuration guards, explicit deployment separation, and complete saved-state verification. Independent network requests overlap while authentication and token refresh remain locked.
- Host process refresh and live FMC compatibility require separate installation and device checks; automated results alone do not establish either.

## 0.3.7 optional lab TLS verification

- 98 automated tests passed; Ruff and plugin/source package validation passed.
- A real local HTTPS fixture confirmed default acceptance of a self-signed certificate with a mismatched hostname, strict rejection of an untrusted issuer, CA-bundle rejection of a hostname mismatch, and successful verification with a matching hostname and trusted certificate.
- Inventory saves preserve strict TLS settings; invalid verification settings and CA bundles fail before connection.
- Automated checks do not establish live FMC API compatibility or desktop-session reload behavior.

## 0.3.6 inventory accounts and deletion

- Local suite: 95 tests passed, including stdio discovery, password migration and rotation, blank-password preservation, deletion of legacy entries, empty inventories, and restoration after a failed YAML write.
- Component bridge checks cover six input fields, password whitespace, clearing entered passwords after save, trash actions, and explicit deletion payloads.
- Ruff passed for changed runtime modules and enrollment tests. Package checks validated version consistency and reproducible archives.
- Installed and refreshed the local plugin and pinned the standalone MCP registration to the exact installed release. A real stdio client verified version 0.3.6, all 16 tools, the app-only save/deletion schema, the resource's username/password/trash controls, and inventory output without password values. No devices were contacted.
- Actual updated form rendering in the current desktop session requires a host restart. Live FMC authentication and Windows execution were not tested.

## 0.3.5 device inventory update

- 89 automated tests pass, including MCP inventory resource/tool round trips, multi-device YAML read-back, validation before writes, credential/settings preservation, and no device requests during inventory saves.
- The Node component test verifies inventory load/edit/save, adding devices, error/retry behavior, and absence of automatic connection calls.
- The app has no password fields, network fetches, loopback listener, or connection check. It uses only the host MCP bridge.
- On 21 October 2026, found that the standalone MCP registration still pointed to 0.3.4 despite the 0.3.5 plugin skill being installed. Installed the current source, refreshed the plugin, and repinned the standalone server. A real stdio client verified the inventory tools, inventory-only resource, and compatibility entrypoint without modifying inventory or contacting devices.
- Actual embedded rendering in the desktop host and Windows execution still require environment verification.


## 0.3.2 enrollment feedback and CI correction

- 86 tests pass locally, including save confirmation, separate FMC connection results, lost/blocked response handling, bounded fetch timeout, native-store failure/retry, and responsive status during a synthetic native-store prompt.
- The card removes domain/CA controls and uses explicit light/dark foreground/background pairs. Credentials stay exclusively in the direct loopback submission.
- Run 39226877614 failed on Windows because a rejected request produced WinError 10053; bounded request bodies are now consumed before rejection. Its macOS job was cancelled by the matrix's fail-fast behavior.
- Run 39226890924 passed on Windows and failed two real stdio tests on macOS with initialization timeouts. CI now uses managed Python instead of the runner's Framework Python, unbuffered subprocess startup, a 60-second initialization budget, independent matrix jobs, and retained test reports. New remote results must be checked after push.
- Live enrollment still requires user password entry and host loopback permission. No live credential values were inspected or supplied during this update.

## 0.3.1 local connection correction

- The installed desktop/CLI loaded the plugin skill but omitted the bundled server from `codex mcp list`, even with compatibility files. Explicit `codex mcp add secure-firewall` now registers the installed stdio helper and reports it enabled.
- Compatibility manifests and launch-file parity are checked; actual in-chat tool discovery and UI rendering still require a refreshed host session. External Python-client success alone is not host integration success.
- No password was obtained, and no live enrollment was completed by this correction.

## 0.3.0 embedded enrollment update

- 83 automated tests pass on macOS, including the MCP resource/tool metadata round trip, JSON loopback submission, exact Origin/Host/authorization rejection, CORS preflight, expiry/replay protection, and password omission from responses, inventory, and logs.
- A Node-based component simulation verifies bridge initialization, device-details tool calls, direct password submission, password clearing, and no password in any host bridge message. This is not a live ChatGPT rendering test.
- The UI resource uses the MCP Apps MIME type, a per-process cache URI, exact loopback CSP allowlist, and global/thread plugin entrypoints. Credentials are not an MCP tool parameter. Existing native-store and inventory behavior is reused.
- Actual in-host rendering, the host sandbox origin, browser private-network permissions, and native credential entry still require a user pilot. Unsupported origins or blocked loopback requests fail closed. No browser enrollment fallback is opened.
- Windows native execution remains unverified locally. FMC configuration and deployment are unchanged.

## 0.2.0 enrollment update

- 81 automated tests pass on macOS, including loopback form submission, cross-origin/Host/CSRF rejection, expiry, one-use completion, mismatched password and missing CA failures, existing-alias protection, and credential omission from responses/logs/inventory. Tests use synthetic credentials and a memory store.
- Ruff and portable package checks pass. The new release is prepared through the existing installer, preserving private enrollment. MCP now exposes 15 tools, adding `start_enrollment` and `enrollment_status`.
- Actual password entry and native credential-store enrollment require the user; live FMC access and Windows execution remain environment checks. The local enrollment form is not a native ChatGPT credential dialog.
- Version 0.1.0 was installed and enabled by the local plugin manager; its 13 tools and health/list calls were verified from the installed cache launch manifest. Work interface activation was not observed.

## Original 0.1.0 build report

Build: **0.1.0**, tested locally on **macOS Apple Silicon**, Python **3.12.12**,
uv **0.10.4**. Tests use synthetic devices and in-memory synthetic credentials;
no user's native credential store or lab device was accessed.

## Verified locally

| Check | Result |
| --- | --- |
| Automated suite | 73 tests pass. |
| Python package coverage | 80% in the measured run; native SSH/store paths remain environment-dependent. |
| Static checks | Ruff passes; Python compiles; macOS shell launchers pass shell syntax checks. |
| Dependency lock | Frozen uv lock check passes, including platform dependency markers. |
| Schema snapshot | Source checksum preserved; sanitized snapshot checksum verified; 1,623 unique operations, 889 paths, 4,052 components. |
| Schema gaps | One unresolved response reference recorded; no external-reference fetching or invented definition. |
| Request boundaries | Typed parameters/bodies, required and semantic fields, bulk shape, cross-domain protection, undeclared headers, and path traversal checks. |
| FMC simulation | Token reuse/refresh limits, ambiguous domains, version constraint, JSON errors, throttling, rejected redirects, uncertain-write reconciliation behavior. |
| Configuration simulation | Create/update/delete read-back, mismatch detection, bulk results, before snapshots, and no implicit deployment. |
| Deployment simulation | Separate tool, readiness/pending snapshot, single-use/expiry/target/scope checks, changed-state refusal, no force/warning bypass, async acceptance distinguished. |
| Secret handling | Synthetic secret-reference resolution, literal-sensitive-field refusal, redacted evidence/errors, and no password CLI option. |
| Pagination/verification | Original-origin paging, foreign link not followed, bounded completeness, rule/list order and meaningful expectations. |
| SSH simulation | Command allowlist, injection refusal, bounded command count, prompt/pager handling, and no enable-password response. |
| MCP | Thirteen tools discovered/called with the official Python client; real subprocess stdio health checks pass in automatic and legacy modes. |
| Real isolated installation | Prepared a fresh temporary per-user release with actual frozen dependencies, copied its launch manifest to a separate simulated host-cache folder, and successfully discovered all 13 tools from there. No inventory was created or credentials read. |
| Upgrade isolation | Temporary-home tests preserve unrelated marketplace entries and private sentinel files, retain prior releases, and keep the old pointer on dependency failure. |
| Packaging | Official portable plugin/MCP JSON schemas validate; skill frontmatter validates; ZIP scope, modes, checksums, and deterministic rebuilds tested. |

The isolated cache check verifies that the launch command is independent of the
manifest's copied location. It does **not** simulate all behavior of ChatGPT's
plugin installer or establish that your actual Work account can import it.

## Requires target environment

- Actual ChatGPT desktop Work discovery/import, role permissions, approvals,
  plugin refresh behavior, and local task tool availability.
- Native macOS Keychain credential enrollment/reuse and any OS access prompts.
- Windows execution, PowerShell policy, runtime installation, Credential Manager,
  and filesystem behavior. Windows code and CI configuration are provided;
  no Windows host or remote CI run was available for this build.
- Live FMC authentication/domain headers, TLS trust, account RBAC, supported
  version behavior, object/policy semantics, concurrency, and schema gaps.
- Live FTD SSH host keys, CLI transitions/prompts, command privileges, and output.
- Optional Work Computer Use/browser availability, sign-in sessions, and UI checks.
- Any actual deployment, HA/cluster dependencies, job completion, or dataplane test.

## Pilot procedure

1. Install on one macOS and one Windows machine. Confirm all 15 tools are present
   in a new local Work task and `assistant_health` returns the expected release.
2. Enroll one lab FMC locally, check TLS/login/domain/version, and compare a
   known network object and policy against expected saved configuration.
3. With an explicitly requested disposable-object test, create/read/update/delete
   it and confirm the FMC evidence. Confirm no deployment was submitted.
4. Optionally enroll an FTD, check automatic host-key acceptance, and compare a
   bounded diagnostic with a manual known-good observation.
5. Test an upgrade while retaining inventory and native credentials.
6. Only with an explicit deployment request, review all pending changes on the
   chosen disposable lab device, submit the separate deployment action, and
   verify job completion and any requested runtime behavior.

No device configuration or deployment was performed during this build. The original build did not install a plugin; subsequent local installation is recorded above. No plugin was uploaded to an account, published publicly, or connected to a workspace marketplace. Repository hosting
is maintained separately; see [REPOSITORIES.md](REPOSITORIES.md).
