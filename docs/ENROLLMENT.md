# Device inventory

## Edit inside ChatGPT or Codex

Ask “Open device inventory” or use the plugin app entrypoint. The embedded form
lists existing devices and lets you add rows. Each device has exactly four fields:

- Device Name
- Hostname/IP Address (without a scheme, path, or port)
- HTTPS port (default 443)
- SSH port (default 22)

Select **Save inventory** to update the local `devices.yaml`. Ports must be whole
numbers from 1 through 65535; device names must be unique. Existing names update
that device; a new name adds a device. Devices omitted from an update remain in
the file. Renaming a row adds a new name and does not delete the old entry.

The form never requests a username or password and has no local connection check.
Saving does not authenticate, contact any device, deploy, change stored credentials,
or write the legacy inventory JSON. Existing account, domain, CA, and other device
settings are preserved. New entries store only the four inventory fields; local
account configuration is required before connecting to them.

The app uses the host MCP tool bridge, with no local HTTP listener or remote
assets. `device_inventory` opens it; `start_enrollment` remains a compatibility
entrypoint and prefills a supplied name/address. `save_device_inventory` validates
all rows before a locked, atomic YAML update. Save errors leave the form editable.
If the response times out, reopen the inventory to inspect saved values before
retrying. If the host cannot render MCP Apps, refresh the plugin and restart the
host; the assistant must not claim the card was displayed or a save completed.

The inventory file is ignored by Git, excluded from release archives, and written
with owner-only permissions on Unix. Existing credentials in the same file remain
private and are never returned to the form or model.

## Terminal alternative

The terminal option separately configures accounts and advanced device settings.
It writes credentials to the same local YAML file; the inventory form does not.

macOS:

```sh
./Manage.command enroll fmc lab-fmc-1 https://fmc.example.invalid --username api-user --domain Global
./Manage.command check lab-fmc-1
```

Windows PowerShell:

```powershell
./Manage.ps1 enroll fmc lab-fmc-1 https://fmc.example.invalid --username api-user --domain Global
./Manage.ps1 check lab-fmc-1
```

Password entry is hidden and repeated once to catch typos. There is no password
argument or environment-variable option. Interactive enrollment is required.

For a lab/private CA, add `--ca-bundle /absolute/path/lab-ca.pem` on macOS, or
`--ca-bundle 'C:\Users\you\Certificates\lab-ca.pem'` on Windows. Certificates
are always verified, including hostnames. There is no insecure TLS switch.
Add `--expected-version-prefix 10.5.` if you want writes blocked on any other
observed version. This is a version constraint, not proof of schema coverage.

Use the domain's exact name or UUID. With multiple accessible domains and no
explicit enrollment choice, the helper refuses to guess and reports candidates.
The API must be enabled, and the account must have the appropriate FMC role.
Prefer a dedicated API account. Cisco documents that sharing credentials
between UI and API sessions can invalidate sessions on supported versions.

Update an enrollment or rotated password by repeating `enroll` with `--replace`.
The credential reference remains stable (`<alias>-auth`). A refreshed enrollment
is read on subsequent tool calls; restart the plugin after password rotation to
discard any still-valid cached FMC token. No token is persisted to disk.

Optional FTD enrollment:

```sh
./Manage.command enroll ftd lab-ftd-1 ftd.example.invalid --username diagnostic-user --fmc-alias lab-fmc-1 --device-uuid DEVICE_UUID
./Manage.command trust-host lab-ftd-1
```

Use `./Manage.ps1` instead on Windows. `trust-host` shows the SSH key fingerprint;
verify it through an independent trusted source and type it exactly. The key is
saved in the private `known_hosts` file. Unknown or changed keys are rejected.
Device UUIDs are optional inventory references and must still be reconciled with
FMC device/HA/cluster records before deployment.

For an API configuration field that needs a secret, enroll it locally:

```sh
./Manage.command set-secret radius-lab-secret
```

In the requested payload, use `{"$secret":"radius-lab-secret"}` in that field.
The helper resolves it internally before validation and transmission. Literal
nonempty sensitive-field values are rejected. Do not use password-like values
in names/descriptions; file storage, redaction, and metadata detection cannot
infer the sensitivity of arbitrary unlabeled text.

The installer keeps `devices.yaml` beside versioned releases so upgrades reuse
it. `devices.example.yaml` is the tracked credential-free format example. The
local file is ignored by Git and excluded from release archives. Unix writes use
mode `0600`; on Windows, permissions inherit the plugin folder's ACLs, so keep
that folder restricted to your user. Inventory and evidence remain in the
per-user app data directories. `SFA_DATA_DIR` is an optional local path override
for isolated tests/approved deployments; it is never provided as an MCP argument.
New inventory entries contain `device_name`, `hostname`, `https_port`, and
`ssh_port`. Existing runtime device metadata remains compatible and is preserved
when updating inventory details. Credentials are configured separately through
local hidden terminal entry; they are never collected by the inventory form.

Browser sign-in is separate. The plugin never reads a stored password into chat
or types it through a model-visible browser tool. Reuse an approved browser
session or complete sign-in through the host's secure user flow when needed.
