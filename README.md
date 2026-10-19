# Secure Firewall Assistant 0.1.0

A private desktop-only plugin for ChatGPT Work on **macOS and Windows**. It uses
the supplied FMC OpenAPI reference, a local MCP helper, a private inventory, and
the native OS credential store. No hosted server, tunnel, or OpenAI API key is
required. Work/model usage follows your ChatGPT plan and workspace settings.

## Start here

1. Install [uv](https://docs.astral.sh/uv/getting-started/installation/) through
   your approved software channel. It installs the pinned Python 3.12 runtime
   and locked dependencies during setup. Setup needs internet access; normal
   helper startup uses the prepared environment with offline dependency resolution.
2. Extract the versioned release ZIP into a folder you own.
3. On macOS, run `./Install.command` in Terminal. On Windows, run `./Install.ps1`
   in PowerShell. Follow organizational script/signing policy; do not disable it.
4. Restart ChatGPT desktop. Open **Plugins**, select your personal marketplace,
   install **Secure Firewall Assistant**, and start a new **local Work** chat.
5. Enroll your devices locally as described in [ENROLLMENT.md](docs/ENROLLMENT.md).
6. Mention the plugin and request a read-only check first.

Use the **release directory printed by the installer** for management commands.
The installer creates a durable per-user release and a personal marketplace
entry. It preserves all other marketplace entries, backups, private inventory,
and credential entries. Upgrading means installing a new reviewed release and
refreshing/reinstalling it in the Plugins interface. See [INSTALLATION.md](docs/INSTALLATION.md).

Examples after enrollment:

- “Configure these network objects on FMC lab-fmc-1: branch-net = 192.0.2.0/24.”
- “Validate that policy Lab-ACP has these rules in this order: …”
- “Check the selected FMC configuration and use enrolled FTD diagnostics if needed.”
- “Deploy all pending changes on device lab-ftd-1, including other users' pending changes.”

The last request has a different effect from configuration. **Configuration never
implicitly triggers deployment.** Explicit deployment uses a fresh pending-change
preview and does not bypass warnings or force deployment.

## Scope and verification

The catalog contains 1,623 operations. JSON reads are available broadly; ordinary
object, policy, and device-subresource configuration writes are available through
the guarded executor. Special operational writes, dynamic mappings/overrides,
and unreviewed write namespaces are discoverable but blocked. Full pending
deployment has its own tool; selective policy deployment is not implemented.
This is a reusable foundation, not a claim that every API operation has been
tested against every FMC version.

The file is OpenAPI 3.0.1, with 889 paths and 4,052 component schemas. Its embedded
version does not establish the device software version. One response reference
is unresolved; the helper reports affected validation as unavailable rather than
inventing a schema. Examples are stripped from the shared snapshot. See
[SCHEMA.md](docs/SCHEMA.md) and [VALIDATION.md](docs/VALIDATION.md).

**Locally verified:** automated mock-device tests, request validation, guardrails,
stdio tool discovery/calls, package structure, and installer/update behavior in
an isolated temporary home. See the validation report for exact results.

**Requires your environment:** actual ChatGPT Work import and permissions, FMC
version/RBAC and live API behavior, macOS Keychain enrollment, Windows native
execution/Credential Manager, SSH prompts, browser availability, and live deployment.
The assistant has not been installed into your ChatGPT account by this build.

## Maintenance

Use a private Git repository, reviewed pull requests, protected release branches,
and tagged ZIP releases. The included macOS/Windows CI workflow runs the test
suite; it has not been run remotely by this build. The two source destinations
and synchronization process are documented in [REPOSITORIES.md](docs/REPOSITORIES.md).
No workspace account is created automatically. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[MAINTENANCE.md](docs/MAINTENANCE.md).

Read [ARCHITECTURE.md](docs/ARCHITECTURE.md) for data flow and trust boundaries.
Never put actual passwords in chat, source files, issue reports, command-line
arguments, environment variables, or support logs.
