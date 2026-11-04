# Shared FMC schema MCP service

By default the plugin uses its bundled FMC 10.5.0.0 schema, revision r2, without
contacting a schema server. To opt into a shared read-only Streamable HTTP MCP
service, create `schema-service.json` in the **private_config_directory** reported
by `assistant_health`, containing:

```json
{"url": "https://schemas.example.org/mcp"}
```

Use your organization's actual endpoint. This local settings file is never
exported. Alternatively set `SFA_SCHEMA_MCP_URL` in the MCP process environment;
it overrides the file (an empty value selects bundled mode). Restart the server
after changing settings. Health reports `schema_service.mode` and the selected URL.
An invalid setting fails explicitly. A configured remote service retains its
cache/outage behavior; it does not silently fall back to the bundled catalog.

The optional service's `/health` reports published versions.
It runs independently of Codex as the `secure-firewall-schemas` systemd service.
The service has no device inventory, credentials, configuration executor, or
write tools. Its six tools list versions, select/download a schema, search API
operations, and describe operations and component definitions.

Each installed plugin retains a local stdio MCP helper. Its discovery tools
accept `target`; the helper detects that FMC's version, obtains a schema package
through the shared HTTP MCP, and performs discovery and validation locally with
the same catalog. Omitting `target` selects the latest published catalog without
contacting an FMC. No separate remote MCP registration is required in Codex:
the local helper is the client of the shared MCP service. Other MCP clients may
also connect directly to the shared endpoint for schema discovery.

Installing/enabling the plugin loads its bundled `secure-firewall` stdio server
through `mcp.json` (or `.mcp.json` for compatibility). It does not create a second
standalone schema-server entry in the client's MCP settings. When configured, the local helper
reaches the shared service when it needs a schema; users need network access. A separately added `secure-firewall` client registration is a
local development convenience, not a requirement imposed on plugin users.
The local bootstrap prepares a delivered package update on the next MCP start;
its stable standalone dispatcher follows the installed plugin version.
After updating the plugin, start a new local chat; an existing
desktop process may retain old tool/resource definitions until restarted.

The supplied, maintained schema is identified as FMC **10.5.0.0, revision r2**,
based on the project owner's version identification. This does not assert live
compatibility with every operation or FMC build. Numeric versions are normalized
to four components; build labels do not change the schema version selection.
An absent version selects the highest numeric published version, even if the
requested FMC is older or newer. The selection, fallback status, revision,
checksum, and remote/cache source appear in discovery and saved evidence.
Existing explicit device `expected_version_prefix` write constraints still apply.

The local helper checks for an update at most once per minute per FMC version.
It pins one immutable Catalog for an entire operation, including bulk worker
threads and read-back. A later operation can use a new revision. Package checksums
and size limits are verified before loading. Packages are atomically cached under
the user's private data directory. If the service cannot be reached, a previously
validated cached package may be used, explicitly reported as cached. Without a
cache the operation stops; malformed online packages are rejected rather than
silently falling back. The bundled file is the default catalog when no remote service is configured;
it also seeds shared registries and supports health/tests.

Only software-version queries and schema content cross this connection; FMC
credentials, REST request bodies, and evidence stay with the local execution
helper. This internal endpoint uses unauthenticated HTTP for read-only metadata.
Checksums detect corruption, not a hostile network replacing both content and
checksum. Put the endpoint behind trusted HTTPS before use outside the trusted
lab network. `SFA_SCHEMA_MCP_URL` overrides the service address for another
installation; it must not embed credentials.

## Publishing corrections and new versions

Runtime source: `/opt/secure-firewall-schema-service`.
Registry: `/var/lib/secure-firewall-schemas`.
The service runs as the unprivileged `secure-firewall-schema` account with a
read-only filesystem sandbox. Schema publishing is an administrative SSH task;
there are deliberately no upload or mutation tools exposed over HTTP.

Validate and sanitize a new source with `scripts/import_schema.py`, apply reviewed
corrections, and test it before publication. On the server, publish the resulting
compressed OpenAPI file using a new revision:

```sh
sudo /opt/secure-firewall-schema-service/.venv/bin/python -m secure_firewall_assistant.cli schema-publish \
  --directory /var/lib/secure-firewall-schemas \
  --schema /path/to/reviewed-fmc.openapi.json.gz \
  --fmc-version 10.5.0.0 --revision r2
```

For another FMC version, change `--fmc-version` and start its own revision.
Published revision identifiers are immutable: different content requires a new
revision. Content-addressed packages and historical revision checksums are retained.
The atomic `index.json` selects each version's active revision and is reread on
requests. No server restart or plugin reinstall is required for schema updates.
Code changes to the service still require deployment and a restart.

`deployment/secure-firewall-schemas.service` records the unit configuration.
Use `systemctl status secure-firewall-schemas` and
`journalctl -u secure-firewall-schemas` for operational checks. Choose a free port
when installing another service and update the endpoint and allowed-host list.
No existing service on this machine is replaced.

## Separate Cisco source and registry repository

The deployed service is backed up at
the maintainer-managed schema repository.
`runtime/` captures deployed source and dependency locks, `deployment/` captures
the installed systemd unit, and `registry/` stores every schema package, active
index, and immutable revision history. `snapshot.json` records each file's SHA-256.
Credentials, device inventory, evidence, logs, and virtual environments are excluded.

After **every** code deployment, service-unit change, or schema publication, run:

```sh
uv run --offline python scripts/sync_schema_repository.py
```

This uses existing admin SSH authentication, validates all registry checksums,
updates the separate checkout, commits changes, pushes without rewriting history,
and verifies the remote commit. `scripts/push_repositories.py` runs it after both
plugin repository pushes and reports a failure if synchronization fails. Changes
made directly on the server also require this command before being considered
complete; this is a release step, not a background file watcher.

For an already authenticated SSH control connection, set the local environment
variable `SFA_SCHEMA_SSH_CONTROL_PATH` or pass `--control-path`. Paths and
authentication details stay local. A local Git setting
`secureFirewall.schemaSshControlPath` can persist the socket choice for this checkout.
