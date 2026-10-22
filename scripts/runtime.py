"""Standard-library bootstrap for installed plugin packages and the stable MCP dispatcher.

No third-party imports or device access. Bootstrap diagnostics go to stderr;
stdout and stdin belong exclusively to the MCP server.
"""
import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

NAME = "secure-firewall-assistant"
TOP = {"plugin.json", "mcp.json", ".mcp.json", "pyproject.toml", "uv.lock", ".python-version",
       "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "NOTICE.md", "Install.command", "Install.ps1",
       "Manage.command", "Manage.ps1", "devices.example.yaml"}
DIRECTORIES = {"src", "scripts", "skills", "docs", "deployment", ".codex-plugin"}
EXCLUDED = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "dist", "build"}


def selected_files(source):
    for path in sorted(source.rglob("*")):
        rel = path.relative_to(source)
        if any(part in EXCLUDED for part in rel.parts):
            continue
        if rel.as_posix() not in TOP and rel.parts[0] not in DIRECTORIES:
            continue
        if path.is_symlink():
            raise RuntimeError("Plugin packages must not contain symlinks")
        if not path.is_file():
            continue
        if (path.name in {"devices.yaml", "devices.yaml.lock", "inventory.json", ".env", "installation.json"}
                or path.name.startswith(".sfa-") or path.suffix in {".pyc", ".log"}):
            continue
        yield path, rel


def source_digest(source):
    digest = hashlib.sha256()
    for path, rel in selected_files(source):
        # Installer-local command discovery must not change the package identity.
        if rel.as_posix() in {"mcp.json", ".mcp.json"}:
            continue
        digest.update(rel.as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def atomic_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".sfa-")
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    atomic_bytes(path, (json.dumps(value, indent=2) + "\n").encode())


@contextmanager
def runtime_lock(base, timeout=180):
    base.mkdir(parents=True, exist_ok=True)
    with (base / "runtime.lock").open("a+b") as handle:
        handle.seek(0)
        handle.write(b"0")
        handle.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Another runtime upgrade is still active; retry startup later") from None
                time.sleep(0.1)
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def runtime_python(release):
    return release / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def stable_transport(base, uv_binary):
    return {"command": str(uv_binary), "args": ["run", "--no-project", "--python", "3.12",
            str(base / "launcher.py"), "--active"], "cwd": str(base)}


def migrate_registration(home, base, uv_binary):
    """Change only transport fields in our existing standalone Codex entry.

    TOML is parsed before and after; all other values, comments, and tables survive.
    Unrecognized/custom server registrations are never replaced.
    """
    config = (home / ".codex/config.toml").resolve()
    if not config.exists():
        return "not_registered"
    original_bytes = config.read_bytes()
    original = original_bytes.decode("utf-8")
    parsed = tomllib.loads(original)
    server = parsed.get("mcp_servers", {}).get("secure-firewall")
    if not isinstance(server, dict):
        return "not_registered"
    desired = stable_transport(base, uv_binary)
    # Existing explicit timeouts remain intact; cold dependency preparation may
    # exceed the client's short default on an upgraded standalone connection.
    if "startup_timeout_sec" not in server:
        desired["startup_timeout_sec"] = 180
    if all(server.get(key) == value for key, value in desired.items()):
        return "stable"
    arguments = server.get("args", [])
    legacy = (isinstance(arguments, list) and "--project" in arguments and
              "secure-firewall-assistant" in arguments and "serve" in arguments)
    if legacy:
        project_index = arguments.index("--project") + 1
        legacy = (Path(server.get("command", "")).name in {"uv", "uv.exe"} and
                  project_index < len(arguments) and
                  Path(arguments[project_index]).resolve().is_relative_to((base / "releases").resolve()))
    dispatcher = isinstance(arguments, list) and str(base / "launcher.py") in arguments
    if server.get("url") or not (legacy or dispatcher):
        return "custom_registration_preserved"
    headers = list(re.finditer(r"(?m)^[ \t]*\[[^\r\n]+\][ \t]*(?:#[^\r\n]*)?(?=\r?$)", original))
    span = None
    for index, header in enumerate(headers):
        try:
            section = tomllib.loads(header.group().strip() + "\n__sfa_probe = true\n")
        except tomllib.TOMLDecodeError:
            continue
        if section.get("mcp_servers", {}).get("secure-firewall", {}).get("__sfa_probe") is True:
            span = (header.end(), headers[index + 1].start() if index + 1 < len(headers) else len(original))
            break
    if span is None:
        raise RuntimeError("Cannot migrate the standalone inline MCP table; use a standard MCP server table")
    body = original[span[0]:span[1]]
    # Remove each existing transport assignment, including multiline arrays/strings.
    for key in desired:
        match = re.search(rf'''(?m)^[ \t]*(?:{key}|"{key}"|'{key}')[ \t]*=''', body)
        if match:
            end = body.find("\n", match.end())
            while True:
                end = len(body) if end < 0 else end + 1
                try:
                    value = tomllib.loads(body[match.start():end])
                    if set(value) != {key}:
                        raise RuntimeError("Unsupported standalone MCP transport assignment")
                    break
                except tomllib.TOMLDecodeError:
                    if end == len(body):
                        raise RuntimeError("Could not parse standalone MCP transport") from None
                    end = body.find("\n", end)
            body = body[:match.start()] + body[end:]
    newline = "\r\n" if "\r\n" in original else "\n"
    assignments = newline + "".join(f"{key} = {json.dumps(value)}{newline}" for key, value in desired.items())
    updated = original[:span[0]] + assignments + body + original[span[1]:]
    expected = copy.deepcopy(parsed)
    expected["mcp_servers"]["secure-firewall"].update(desired)
    if tomllib.loads(updated) != expected:
        raise RuntimeError("Standalone MCP migration would alter unrelated configuration")
    if config.read_bytes() != original_bytes:
        raise RuntimeError("Codex configuration changed during migration; retry startup")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    atomic_bytes(config.with_name(f"config.sfa-backup-{stamp}.toml"), original_bytes)
    atomic_bytes(config, updated.encode())
    return "migrated"


def clean_environment():
    return {key: value for key, value in os.environ.items() if key not in {"VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME"}}


def prepare(source, home=None, uv_binary=None, runner=subprocess.run, *, allow_downgrade=False,
            package_root_is_release=False):
    source, home = Path(source).resolve(), (home or Path.home()).resolve()
    manifest = json.loads((source / "plugin.json").read_text(encoding="utf-8"))
    version = manifest.get("version", "")
    if manifest.get("name") != NAME or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise RuntimeError("Unrecognized plugin identity or version")
    uv_binary = uv_binary or shutil.which("uv")
    if not uv_binary:
        raise RuntimeError("Install uv and restart the desktop app before starting this plugin")
    uv_binary = str(Path(uv_binary).resolve())
    base = home / ".codex/plugins" / NAME
    digest = source_digest(source)
    release = base / "releases" / f"{version}-{digest[:12]}"
    with runtime_lock(base):
        ready = release / "installation.json"
        marker = json.loads(ready.read_text()) if ready.exists() else {}
        if marker.get("source_sha256") != digest or not runtime_python(release).is_file():
            if source != release:
                for path, relative in selected_files(source):
                    target = release / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, target)
                if source_digest(release) != digest:
                    raise RuntimeError("Plugin files changed during preparation; retry after the host finishes updating")
            runner([uv_binary, "sync", "--project", str(release), "--frozen", "--no-dev"],
                   check=True, env=clean_environment(), stdout=sys.stderr)
            with tempfile.TemporaryDirectory(prefix=".installation-check-", dir=release) as private:
                runner([str(runtime_python(release)), "-m", "secure_firewall_assistant.cli", "health"],
                       check=True, env={**clean_environment(), "SFA_DATA_DIR": private}, stdout=subprocess.DEVNULL)
            write_json(ready, {"version": version, "source_sha256": digest,
                              "installed_utc": datetime.now(timezone.utc).isoformat()})
        active_path = base / "active.json"
        active = json.loads(active_path.read_text()) if active_path.exists() else {}
        previous_version = tuple(map(int, active.get("version", "0.0.0").split(".")))
        if allow_downgrade or tuple(map(int, version.split("."))) >= previous_version:
            launcher_source = source / "scripts/runtime.py"
            atomic_bytes(base / "launcher.py", (launcher_source if launcher_source.is_file() else Path(__file__)).read_bytes())
            migration = migrate_registration(home, base, uv_binary)
            write_json(active_path, {"version": version, "release_directory": str(release), "source_sha256": digest,
                                     "plugin_root": str(release if package_root_is_release else source),
                                     "runtime_home": str(home),
                                     "uv_binary": uv_binary,
                                     "codex_binary": shutil.which("codex") or active.get("codex_binary")})
        else:
            migration = migrate_registration(home, base, uv_binary)
    return {"version": version, "release_directory": str(release),
            "standalone_mcp": migration, "stable_launcher": str(base / "launcher.py")}


def active_release(base):
    state = json.loads((base / "active.json").read_text())
    release = Path(state["release_directory"]).resolve()
    if release.parent != (base / "releases").resolve() or not runtime_python(release).is_file():
        raise RuntimeError("The selected runtime is unavailable; refresh the plugin to prepare it")
    marker = json.loads((release / "installation.json").read_text())
    if marker.get("source_sha256") != state.get("source_sha256") or marker.get("version") != state.get("version"):
        raise RuntimeError("The selected runtime does not match its completed installation")
    return release


def installed_source(home, codex_binary, runner=subprocess.run):
    """Resolve the installed package through the supported CLI, never by choosing
    the newest leftover cache directory. This also supports hosts using only the
    standalone registration rather than starting the bundled MCP process.
    """
    result = runner([codex_binary, "plugin", "list", "--json"], capture_output=True, text=True,
                    check=True, timeout=30, env=clean_environment())
    entries = [item for item in json.loads(result.stdout).get("installed", [])
               if item.get("name") == NAME and item.get("installed") and item.get("enabled")]
    if len(entries) > 1:
        raise RuntimeError("Multiple enabled Secure Firewall plugins are installed; select one before starting the standalone MCP")
    if not entries:
        return None
    entry = entries[0]
    version, marketplace = entry.get("version", ""), entry.get("marketplaceName", "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version) or not re.fullmatch(r"[A-Za-z0-9_.-]+", marketplace):
        raise RuntimeError("The installed plugin has an unsupported version or marketplace identity")
    cache = home / ".codex/plugins/cache" / marketplace / NAME
    candidates = [cache / version, cache / "local"]
    source = entry.get("source", {})
    if source.get("source") == "local" and source.get("path"):
        candidates.append(Path(source["path"]))
    for candidate in candidates:
        manifest = candidate / "plugin.json"
        if manifest.is_file():
            value = json.loads(manifest.read_text(encoding="utf-8"))
            if value.get("name") == NAME and value.get("version") == version:
                return candidate if (candidate / "scripts/runtime.py").is_file() else None
    raise RuntimeError("The installed plugin package is unavailable; finish the host's plugin refresh")


def active_source(base):
    state = json.loads((base / "active.json").read_text())
    home = Path(state.get("runtime_home", base.parents[2])).resolve()
    codex_binary = shutil.which("codex") or state.get("codex_binary")
    # An explicitly isolated runtime home must not inspect the real user's CLI.
    source = installed_source(home, codex_binary) if home == Path.home().resolve() and codex_binary else None
    if source is None:
        candidate = Path(state.get("plugin_root", ""))
        source = candidate if (candidate / "scripts/runtime.py").is_file() else None
    return source, home, state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--active", action="store_true")
    parser.add_argument("--runtime-home", type=Path, help="Isolated runtime home for testing or managed installations")
    parser.add_argument("--uv", help="Existing uv executable discovered during installation")
    args = parser.parse_args()
    try:
        if args.active:
            base = Path(__file__).resolve().parent
            source, home, state = active_source(base)
            if source is not None:
                # Delegate to the updated package's bootstrap too, so future
                # changes to dependency preparation take effect immediately.
                command = [sys.executable, str(source / "scripts/runtime.py"), "--source", str(source),
                           "--runtime-home", str(home)]
                if state.get("uv_binary"):
                    command += ["--uv", state["uv_binary"]]
                raise SystemExit(subprocess.call(command, env=clean_environment()))
            release = active_release(base)
        else:
            result = prepare(args.source or Path(__file__).resolve().parents[1], home=args.runtime_home, uv_binary=args.uv)
            release = Path(result["release_directory"])
        # The server alone inherits protocol streams. No bootstrap JSON on stdout.
        raise SystemExit(subprocess.call([str(runtime_python(release)), "-u", "-m", "secure_firewall_assistant.cli", "serve"],
                                        env=clean_environment()))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(f"Secure Firewall runtime startup failed: {detail}. "
              "Check dependency access and local installation/configuration. No incomplete runtime was activated.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
