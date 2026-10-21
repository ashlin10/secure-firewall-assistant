# Private enrollment

## Enroll inside ChatGPT or Codex

Ask: “Enroll a device.” `start_enrollment` returns an **embedded MCP App card
inside the conversation**, not a browser URL. Enter the alias, address, username,
and password in the card, then select **Save enrollment**. An existing alias can
be re-enrolled when its type, address, and username match; the form preserves its
other saved details. Different details require a new alias. The card confirms the saved enrollment
through a status read and checks FMC connectivity separately. If a save response
times out, select **Check enrollment status** before retrying.

You can also open **Secure Firewall enrollment** through the plugin's app
entrypoint and complete the device details and password in the same card.

Security boundaries:

- Password fields are never sent through MCP tools, chat messages, model-context
  updates, widget state, console logs, or server request logs.
- Safe device details and completion status can reach the model. A per-session
  authorization value and loopback endpoint are delivered as widget-only `_meta`.
- The listener binds only to 127.0.0.1. Each session expires after ten minutes,
  checks an unguessable authorization header and exact Host/Origin, and becomes
  unusable after a successful save. No GET/browser enrollment page is served.
- The UI resource permits connections only to that helper's exact loopback
  origin and loads no remote assets. Cross-origin submissions are restricted to
  the documented default ChatGPT sandbox origin. Other host origins fail closed.
- Local-network/browser sandbox permission may be required. If the host cannot
  render MCP Apps or cannot reach loopback, show an error; never silently open a
  browser, request a password in chat, or route it through tool arguments.
- The card checks loopback connectivity before revealing the password fields.
  If the host blocks the cross-origin iframe's loopback request, the card reports
  that no password was sent. The embedding host must delegate loopback access;
  plugin code cannot grant that host-level permission.
- The helper uses local HTTP for the loopback channel. FMC HTTPS validation
  remains enabled. Credentials and device details are saved in clear text in
  `devices.yaml` in the plugin's local folder. On Unix systems, the file is
  written with owner-only permissions. Keep it out of Git repositories, backups,
  and synced folders. It remains accessible to processes and people with access
  to your account or computer.

Verified protocol support and JavaScript component tests do not establish that every
ChatGPT/Codex rollout permits inline UI to reach a local listener. Test the card
in a fresh local chat after updating the plugin.

## Terminal alternative

The terminal option is retained for device types or options not present in the
card. It writes credentials to the same local YAML file.

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
The card writes the device record under `devices` and its password under
`credentials`, keyed by `credential_ref`. You can add a device by copying the
sample structure into the local file, with matching alias and credential
reference. Quote passwords that contain YAML punctuation; the card handles
quoting automatically.
Existing Keychain/Credential Manager entries are not migrated or used by this
version. Re-enroll each existing alias through the card; the old OS entries can
be removed separately after confirming the YAML-backed connection works.

Browser sign-in is separate. The plugin never reads a stored password into chat
or types it through a model-visible browser tool. Reuse an approved browser
session or complete sign-in through the host's secure user flow when needed.
