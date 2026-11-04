# Export and import

## Export

From a reviewed source checkout with uv installed:

```sh
uv sync --frozen
uv run --offline python scripts/package.py --output dist
```

Share `secure-firewall-assistant-<version>-plugin.zip` and its matching line from
`SHA256SUMS` over your chosen trusted channel. The source ZIP is for maintainers;
it also contains tests, CI, and repository/deployment maintenance settings.
The plugin ZIP excludes those maintainer settings and includes the locked
runtime source, bundled schema, skills, forms, and installers.

Do not ZIP an installed cache or runtime directory: local manifests may contain
an absolute uv path, and runtime state contains private paths or inventory.
The exported source manifests use `uv` and `${PLUGIN_ROOT}`. Personal paths in
`active.json`, MCP registration, or installation output are generated locally
and are expected; they are never part of the recipient package.
Packaging rejects personal home paths and private/generated artifacts in its
include set. Neither ZIP includes device inventory, credentials, evidence,
virtual environments, local settings, or machine-specific MCP registration.

## Import on another computer

1. Install uv using your approved software channel.
2. Verify the received checksum and extract the ZIP into a folder you own.
3. Run `./Install.command` on macOS, or `./Install.ps1` on Windows.
4. Enable Secure Firewall Assistant from the local personal marketplace in your
   supported desktop host. Restart it and start a new local chat.
5. Ask for assistant health. A new installation starts with no enrolled devices;
   existing recipients keep their own inventory on upgrade.
6. Ask to enroll devices and enter your own accounts in the local form.

Initial setup downloads Python 3.12 and locked dependencies. Device operations
require network access to the recipient's devices. API discovery uses the bundled
FMC 10.5.0.0 r2 schema by default; other versions report `latest_fallback`.
For automatic shared schema updates, configure your organization's endpoint as
shown in [SCHEMA-SERVICE.md](SCHEMA-SERVICE.md).

This is a local-executor plugin, not a hosted connector. A ZIP/account upload
cannot enable device access in cloud-only chats or override workspace policy.
Host plugin import/discovery varies; see [INSTALLATION.md](INSTALLATION.md) for
the standalone MCP fallback when bundled-server discovery is unavailable.
Windows execution and desktop rendering need validation on the recipient host.
