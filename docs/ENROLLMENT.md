# Device inventory

## Enrol new devices

Ask “Enrol devices”. `start_enrollment` opens a dedicated form with only new
rows. Existing devices and their details are never included in its initial
response or save response. Select **Save new devices** to add the entered rows.
An existing name is rejected without overwriting it; enrollment cannot delete
devices. After saving, the form clears for another new device.

## Edit inside ChatGPT or Codex

Ask “Open device inventory” or use the plugin app entrypoint. The embedded form
lists existing devices and lets you add rows. Each device has six fields:

- Device Name
- Hostname/IP Address (without a scheme, path, or port)
- HTTPS port (default 443)
- SSH port (default 22)
- Username
- Password (masked during entry)

Select **Save inventory** to update local `devices.yaml`. Username and password
are stored in clear text under each device. A blank password preserves the saved
password; existing passwords are never sent back to the app or model. A password
requires a username. Leaving both blank supports inventory-only devices.

Use the trash icon next to a device to remove its row, then save to delete it.
Deletion also removes its legacy inventory entry and associated login reference.
All devices can be deleted. Renaming a row adds a new alias and preserves the
original; use its trash icon to delete the original explicitly. Advanced settings
belong to the original alias. Omitted devices are preserved unless
explicitly named for deletion. Ports must be integers from 1 through 65535 and
device names must be unique. Saving does not contact devices or deploy.

The app uses the host MCP tool bridge, with no local listener or remote assets.
`device_inventory` opens the inventory editor; `start_enrollment` opens the
separate new-device form and can prefill a supplied name/address.
The app-only `save_device_inventory` tool validates all rows and deletion names
before writing. Save errors leave the form editable. After a timeout, reopen the
inventory to inspect saved values before retrying. Refresh the plugin and restart
the host if it cannot render MCP Apps.

Legacy top-level `credentials` entries migrate into the matching device's
`password` field on save. API-only references remain in `secrets`, with no separate
login credentials section. Migration saves a private
`.sfa-devices-pre-inline.backup` beside the YAML before replacing the old format.
Restore that backup before rolling back to a release without inline passwords.
The inventory and migration backup are excluded from Git and release archives;
Unix writes use owner-only permissions. The password field uses the host's MCP
bridge; it is app-visible only, and responses contain no saved passwords.

## Terminal alternative

The terminal option separately configures accounts and advanced device settings.
It writes the password under the device in the same local YAML file.

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

Lab HTTPS accepts self-signed certificates by default, including when connecting
by IP with a hostname mismatch. To enable certificate and hostname verification,
set `verify_ssl: true` in local device metadata or enroll with `--verify-ssl`.
The inventory form preserves this advanced setting on save.

For a lab/private CA with verification enabled, add
`--ca-bundle /absolute/path/lab-ca.pem` on macOS, or
`--ca-bundle 'C:\Users\you\Certificates\lab-ca.pem'` on Windows. Providing a CA
bundle enables certificate and hostname verification even when
`verify_ssl` is false.
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
New inventory entries contain `device_name`, `hostname`, `https_port`,
`ssh_port`, `username`, and `password`. Existing runtime metadata is preserved
when editing the same device name. Credentials can be entered through the
inventory app or local hidden terminal entry.

Browser sign-in is separate. The plugin never reads a stored password into chat
or types it through a model-visible browser tool. Reuse an approved browser
session or complete sign-in through the host's secure user flow when needed.

## Device categories (0.4.0)

The form includes a Device type dropdown: FMC, FTD, Endpoint, Traffic generator,
Router, and Switch. YAML format 2 stores these under the top-level `fmc`, `ftd`,
`endpoints`, `traffic_generators`, `routers`, and `switches` mappings. Empty
categories remain present. Aliases must be unique across categories. Changing a
type moves its entry while retaining its account; blank passwords preserve the
saved password. Entries without a type in old format-1 files default to FMC.
Existing explicit FTD types are preserved. Legacy metadata and API-only secrets
are retained, and `.sfa-devices-pre-grouped.backup` preserves the pre-migration file.
The form never exposes saved passwords. These new categories provide inventory
storage; they do not add execution adapters for endpoints, routers, switches, or
traffic generators.
