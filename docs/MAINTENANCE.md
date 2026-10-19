# Team distribution and maintenance

The source destinations and dual-host synchronization process are documented in
[REPOSITORIES.md](REPOSITORIES.md). No account plugin, public listing, or workspace
has been created by the local build.
Keep personal enrollment, evidence, tokens, CA/private-key files, and real-device
fixtures outside this repository. The release builder uses an explicit include
list and excludes virtual environments, dependency caches, and private state.

Protect the main/release branches. Teammates propose changes through pull
requests; maintainers review API effects, credential handling, and expected-vs-
observed verification. Use the included macOS/Windows CI matrix. Unit and stdio
tests use synthetic stores/devices; native store and live-device testing are
separate pilot checks. CI configuration is supplied but has not run remotely.

Bump the version in `pyproject.toml`, `plugin.json`, `__init__.py`, service/server
metadata, README, and changelog together, then refresh `uv.lock`. Validate before
creating a tag. The packager checks version consistency and local manifests.
Publish the ZIP, SHA256SUMS, validation report, and changelog on your controlled
release channel. Checksums detect corruption; authenticity depends on your
authenticated release channel or your organization's signing process.

An admin can later import the repo's `.agents/plugins/marketplace.json` through
Admin → Plugins → Import marketplace. Use a reviewed release branch or a pinned
tag/commit, configure role availability, and pilot that exact installation path.
An imported local MCP package must still have a prepared local runtime. The
per-user installer is the baseline; workspace import alone is not a dependency
installer. Do not combine an untested workspace policy with claims of unattended
cross-platform installation.

Installation/upgrades never enroll credentials. Private state uses format v1;
updating an enrollment makes an inventory backup. Future migrations must preserve
native-store reference names, support rollback, back up before writing, and
include state-preservation tests. No deletion of private state occurs during a
normal update or software uninstall.

To add an operational API, implement and test its effects/authorization boundary
explicitly. Do not weaken the generic deployment guard. To add a diagnostic
command, confirm read-only behavior and safe output/privilege requirements on
the relevant FTD version, then update the allowlist and documentation.
