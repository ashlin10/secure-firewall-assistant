# Install and upgrade

This release is a private local plugin package. The ZIP is a transport container;
installation uses ChatGPT desktop's documented local marketplace mechanism. It
is not a cloud MCP deployment or a public-directory submission.

## Prerequisites

- macOS or Windows, ChatGPT desktop, local Work access, and permitted local MCP
  plugins. Workspace entitlement, app rollout, and administrator restrictions
  remain installation checks; this build does not verify your plan or permissions.
- [uv](https://docs.astral.sh/uv/getting-started/installation/) available locally.
  Use an approved installer/package manager; do not bypass your device policy.
- Internet for the initial Python/dependency installation, and local network
  access to your enrolled lab devices for actual operations.
- A writable local plugin folder for `devices.yaml`. No cloud vault account or OpenAI API key.

## Install

Verify the ZIP checksum against the maintainer's authenticated release channel.
Extract it. On macOS, make the included `.command` files executable if your
extractor did not preserve modes, then run `./Install.command`. On Windows,
run `./Install.ps1` in PowerShell under your existing script policy. The scripts
do not change execution policy or request administrator privileges.

Installation:

1. Copies the release into
   `~/.codex/plugins/secure-firewall-assistant/releases/<version>-<digest>/`.
2. Runs a frozen dependency installation and a harmless local health check.
3. Rewrites the installed MCP launch entry to the absolute uv path and prepared
   release directory. The shared archive contains no teammate-specific paths.
4. Adds/updates only this plugin's entry in
   `~/.agents/plugins/marketplace.json`, preserving other entries and backing up
   an existing catalog. It does not directly edit ChatGPT's plugin cache.
5. Prints the exact installed directory and next steps.

Restart ChatGPT desktop, select your personal marketplace in **Plugins**,
install **Secure Firewall Assistant**, and start a new local Work chat. Mention
the plugin and request “Check assistant health and list enrolled device aliases.”
No devices should appear until you enroll them locally.

The portable plugin has `requires_local_executor: true`. Local stdio MCP support
is documented; actual app discovery, cache refresh behavior, and role permission
prompts need a pilot on your Work installation. Installation scripts cannot
override a denied workspace capability. They do not install into your account
or make the helper available to a cloud-only chat.

If marketplace visibility is unavailable but the desktop client permits manual
MCP registration, use Settings → MCP servers → Add server → STDIO with the
exact command/arguments in the installed `mcp.json`. This adds tools only; the
plugin/skill still needs the supported local plugin installation path. Do not
silently claim the assistant skill is installed through MCP registration alone.

## Upgrade or roll back

Download and inspect a reviewed versioned release; run its installer; then
refresh/reinstall from the marketplace and start a new chat. The installer
retains earlier release directories so running processes and rollback remain
available. It leaves the shared `devices.yaml` beside the release directories
untouched.

To select a previous successfully installed release:

```sh
./Install.command --rollback PREVIOUS_RELEASE_DIRECTORY_NAME
```

On Windows use `./Install.ps1 -Rollback PREVIOUS_RELEASE_DIRECTORY_NAME`.
Then refresh the plugin in ChatGPT. Do not delete old releases until no task is
using them. Version 0.3.6 migrates legacy credentials into per-device passwords on save.
Restore the private pre-migration YAML backup before rolling back to an older
release. Unknown future formats are rejected rather than overwritten.

## Failure and removal

If dependencies fail to install, the marketplace pointer is not advanced. Review
the uv output for dependency/network errors. The installer leaves private
enrollment untouched. Existing marketplace JSON that cannot be understood is
left intact. A stale `.sfa-install.lock` can be removed after confirming no
installer is active.

Uninstall through ChatGPT's Plugins interface. Remove only this plugin's personal
marketplace entry and release directories if you want to remove local software.
Private inventory/evidence and `devices.yaml` are intentionally retained; delete
them explicitly if desired. Never remove another plugin's entry or reset the
entire marketplace file.

This source-based installer is not a signed/notarized native application. A
managed organization may require approved packaging or signing before rollout.
No signing identity or Windows certificate is included.

## If skills load but tools do not

A successful plugin installation or visible skill does not prove that the
bundled MCP server was discovered. Check `codex mcp list --json` and inspect only
the secure-firewall entry. This machine loaded portable plugin skills while
omitting the bundled server, including after adding compatibility manifests.

The verified local workaround is explicit registration using the installed
release directory printed by setup. Substitute that exact directory below:

```sh
codex mcp add secure-firewall -- /absolute/path/to/uv run --project /installed/release/directory --frozen --no-dev --offline secure-firewall-assistant serve
```

Keep the installed plugin enabled for its skill. This additional local server
registration supplies the tools and MCP App resource; it does not copy or expose
credentials. Restart the desktop app and use a fresh local chat to load the new
connection. A current chat cannot acquire tool definitions by printing a tool
response from an external test process. Confirm the form actually renders before
claiming enrollment succeeded. The standard MCP status `auth_status: unsupported`
for this local stdio server refers to MCP OAuth, not to the FMC password store.

This registration pins a release path. After an upgrade, repeat it with the new
installed release directory. If a future desktop version discovers the bundled
server automatically, remove only the duplicate standalone registration with
`codex mcp remove secure-firewall`; keep the plugin installed.
