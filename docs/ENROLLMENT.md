# Private enrollment

## Enroll inside ChatGPT or Codex

Ask: “Enroll FMC lab-fmc-1 at https://my-fmc using username api-user.”
`start_enrollment` returns an **embedded MCP App card inside the conversation**,
not a browser URL. Enter and repeat the password in that card, optionally set
an exact domain and local CA bundle path, then select **Save enrollment**.
The password goes directly from the card to a short-lived loopback endpoint and
then to Keychain/Credential Manager. Return to chat and say “done” to check
connectivity. Existing aliases cannot be overwritten through the form.

You can also open **Secure Firewall enrollment** through the plugin's app
entrypoint, enter the FMC name/address/username, select **Continue**, then save
the credential. This uses ChatGPT's plugin UI, without a browser window.

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
- The helper uses local HTTP for the loopback channel. FMC HTTPS validation
  remains enabled. Native store/host/network observability still follows your
  OS and workspace controls; this does not claim protection from local malware.

Verified protocol support and JavaScript component tests do not establish that every
ChatGPT/Codex rollout permits inline UI to reach a local listener. Test the card
in a fresh local chat after updating the plugin. The terminal alternative below
remains available only when deliberately chosen by the user.

## Terminal alternative

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
