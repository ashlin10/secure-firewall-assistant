# Validation report — 19 October 2026

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

1. Install on one macOS and one Windows machine. Confirm all 13 tools are present
   in a new local Work task and `assistant_health` returns the expected release.
2. Enroll one lab FMC locally, check TLS/login/domain/version, and compare a
   known network object and policy against expected saved configuration.
3. With an explicitly requested disposable-object test, create/read/update/delete
   it and confirm the FMC evidence. Confirm no deployment was submitted.
4. Optionally enroll an FTD, verify its host key independently, and compare a
   bounded diagnostic with a manual known-good observation.
5. Test an upgrade while retaining inventory and native credentials.
6. Only with an explicit deployment request, review all pending changes on the
   chosen disposable lab device, submit the separate deployment action, and
   verify job completion and any requested runtime behavior.

No device configuration or deployment was performed during this build. No
plugin was uploaded to an account, installed in the user's current desktop,
published publicly, or connected to a workspace marketplace. Repository hosting
is maintained separately; see [REPOSITORIES.md](REPOSITORIES.md).
