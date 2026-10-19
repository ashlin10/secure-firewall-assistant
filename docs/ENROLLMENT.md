# Private enrollment

Run these commands yourself in your terminal, from the installed release
directory printed by setup. Replace example addresses with your own values.
They are illustrative documentation addresses, not enrolled devices.

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
The helper chooses macOS Keychain or Windows Credential Manager explicitly and
refuses plaintext fallback backends. Initial OS access prompts or an unlocked
credential store may be necessary. Credential access is under your local user
account; it is not an isolated hardware vault inaccessible to other approved
processes running as that user.

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
in names/descriptions; native stores, redaction, and metadata detection cannot
infer the sensitivity of arbitrary unlabeled text.

Inventory and evidence paths are shown by `health`. macOS uses the per-user
Application Support directory; Windows uses platform-specific per-user app
directories. Unix private directories/files use restrictive modes; Windows
inherits the user profile's ACLs. Do not relocate private data into shared or
synced source folders. `SFA_DATA_DIR` is an optional local path override for
isolated tests/approved deployments; it is never provided as an MCP argument.

Browser sign-in is separate. The plugin never reads a stored password into chat
or types it through a model-visible browser tool. Reuse an approved browser
session or complete sign-in through the host's secure user flow when needed.
