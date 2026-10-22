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
3. Keeps the bundled launch command rooted at `${PLUGIN_ROOT}` and discovers
   the local uv executable. Creates a stable standalone dispatcher and migrates
   an existing project-managed `secure-firewall` registration automatically,
   preserving unrelated settings and backing up the configuration.
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

When the host delivers an updated plugin package through a supported marketplace
or workspace sync, the next MCP startup prepares its runtime automatically. Users
do not rerun the installer or edit a version-specific MCP path for each update.
First preparation installs the locked dependencies and checks health; later starts
reuse the ready runtime. Dependency or health-check failure stops the new startup
and leaves the previous active runtime selected. Updates that add uncached
dependencies require network access during preparation.

The stable standalone dispatcher resolves the enabled installed plugin through
`codex plugin list --json`, then delegates to that package's bootstrap. It uses the
CLI's selected version, not the highest leftover cache directory. If the Codex CLI
is unavailable, it can refresh an existing package root or use the last prepared
runtime; it cannot discover a newly selected cache directory without the CLI.
Multiple enabled copies of this plugin require choosing one. Custom standalone
servers with the same name are preserved rather than overwritten.

An initial upgrade from a pre-0.5.0 installation must deliver this new bootstrap
once: run the installer and refresh the plugin, or let a supported host deliver
the new package and launch its bundled MCP. That startup also migrates the legacy
standalone registration. For hosts that omit bundled MCP discovery, run the
installer once to migrate their pinned standalone registration.

The installer remains available for initial setup, local ZIP distribution, and
explicit upgrades or rollback. A source commit alone does not deliver a new
package to other users: the configured distribution channel must sync or publish
it. This implementation does not create or configure a workspace marketplace.
Start a new chat, or restart the desktop host if it retains an older MCP process.
Earlier release directories remain available for running processes and rollback.
The shared `devices.yaml` beside the release directories is unchanged.

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

The installer now migrates an existing project-managed registration to a stable
dispatcher. If there is no standalone entry and your host needs the workaround,
add one once using the stable launcher path printed by the installer:

```sh
codex mcp add secure-firewall -- /absolute/path/to/uv run --no-project --python 3.12 /user/plugin/base/launcher.py --active
```

Keep the installed plugin enabled for its skill. This additional local server
registration supplies the tools and MCP App resource; it does not copy or expose
credentials. Restart the desktop app and use a fresh local chat to load the new
connection. A current chat cannot acquire tool definitions by printing a tool
response from an external test process. Confirm the form actually renders before
claiming enrollment succeeded. The standard MCP status `auth_status: unsupported`
for this local stdio server refers to MCP OAuth, not to the FMC password store.

This registration keeps the same launch path across upgrades. The dispatcher
prepares and selects the installed plugin runtime on startup. If your desktop
version discovers the bundled server automatically, remove only the duplicate
standalone registration with
`codex mcp remove secure-firewall`; keep the plugin installed.

## Shared schemas and format-2 inventory (0.4.0)

Codex clients retain the local plugin and stdio execution server. They must also
reach `http://10.196.150.41:8765/mcp` on the trusted lab network for initial schema
selection. Later operations can use cached schemas if that service is unavailable.
The registry is a separately hosted read-only HTTP MCP, not a cloud-hosted device
executor. See [SCHEMA-SERVICE.md](SCHEMA-SERVICE.md) for publishing schema updates.

The inventory form writes format-2 grouped YAML with a device-type dropdown.
Before using a pre-0.4.0 plugin again, restore the private pre-grouping backup;
older releases do not understand format 2. Installation itself leaves inventory
unchanged; saving through the new helper performs the migration. Start a new chat
or restart the host before editing inventory with the updated tools.
