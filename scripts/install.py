"""Install/update a private local plugin without touching inventory or credentials."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

NAME = "secure-firewall-assistant"
EXCLUDED = {".git", ".venv", ".pytest_cache", ".ruff_cache", "__pycache__", "dist", "build", ".github", "tests"}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".sfa-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(value, out, indent=2)
            out.write("\n")
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def source_digest(source):
    digest = hashlib.sha256()
    for file in sorted(source.rglob("*")):
        rel = file.relative_to(source)
        if file.is_file() and not any(p in EXCLUDED for p in rel.parts) and not file.name.startswith("."):
            digest.update(rel.as_posix().encode())
            digest.update(file.read_bytes())
    return digest.hexdigest()


def register(home, destination):
    marketplace = home / ".agents/plugins/marketplace.json"
    marketplace.parent.mkdir(parents=True, exist_ok=True)
    lock_path = marketplace.parent / ".sfa-install.lock"
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise RuntimeError("Another installer is active. If it was interrupted, remove .sfa-install.lock after checking.") from None
    try:
        os.close(fd)
        if marketplace.exists():
            catalog = json.loads(marketplace.read_text(encoding="utf-8"))
            if not isinstance(catalog, dict) or not isinstance(catalog.get("plugins"), list) or not catalog.get("name"):
                raise RuntimeError("Existing marketplace is not a recognized JSON catalog; it was left unchanged.")
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            shutil.copy2(marketplace, marketplace.with_name(f"marketplace.backup-{stamp}.json"))
        else:
            catalog = {"name": "personal-local", "interface": {"displayName": "Personal local plugins"}, "plugins": []}
        try:
            relative = destination.relative_to(home)
        except ValueError:
            raise RuntimeError("Plugin must be inside the personal marketplace root.") from None
        entry = {"name": NAME, "source": {"source": "local", "path": "./" + relative.as_posix()},
                 "policy": {"installation": "AVAILABLE", "authentication": "ON_USE"}, "category": "Developer Tools"}
        existing = next((e for e in catalog["plugins"] if e.get("name") == NAME), None)
        if existing:
            existing["source"] = entry["source"]
        else:
            catalog["plugins"].append(entry)
        write_json(marketplace, catalog)
        return marketplace
    finally:
        lock_path.unlink(missing_ok=True)


def install(source: Path, home: Path | None = None, uv_binary: str | None = None, runner=subprocess.run):
    home = (home or Path.home()).resolve()
    source = source.resolve()
    manifest = json.loads((source / "plugin.json").read_text(encoding="utf-8"))
    if manifest.get("name") != NAME or not re.fullmatch(r"\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?", manifest.get("version", "")):
        raise RuntimeError("Unrecognized plugin identity or version.")
    uv_binary = uv_binary or shutil.which("uv")
    if not uv_binary:
        raise RuntimeError("Install uv from https://docs.astral.sh/uv/getting-started/installation/ and reopen your terminal.")
    uv_binary = str(Path(uv_binary).resolve())
    version = manifest["version"]
    destination = home / ".codex/plugins" / NAME / "releases" / f"{version}-{source_digest(source)[:12]}"
    if (source / "installation.json").exists():
        destination = source
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        shutil.copytree(source, destination, ignore=shutil.ignore_patterns(*EXCLUDED, ".DS_Store", ".coverage"))
    # The host may copy the manifest into its cache. Start the prepared, immutable
    # release directory rather than expecting dependencies to survive that copy.
    mcp = json.loads((destination / "mcp.json").read_text(encoding="utf-8"))
    transport = mcp["mcpServers"]["secure-firewall"]
    transport["command"] = uv_binary
    transport["args"] = ["run", "--project", str(destination), "--frozen", "--no-dev", "--offline",
                         "secure-firewall-assistant", "serve"]
    transport["cwd"] = str(destination)
    write_json(destination / "mcp.json", mcp)
    # No local credentials are enrolled or read by installation or health checks.
    runner([uv_binary, "sync", "--project", str(destination), "--frozen", "--no-dev"], check=True)
    environment = {**os.environ, "SFA_DATA_DIR": str(destination / ".installation-check")}
    try:
        runner([uv_binary, "run", "--project", str(destination), "--frozen", "--no-dev", "--offline",
                "secure-firewall-assistant", "health"], check=True, env=environment, stdout=subprocess.DEVNULL)
    finally:
        shutil.rmtree(destination / ".installation-check", ignore_errors=True)
    write_json(destination / "installation.json", {"version": version, "source_sha256": source_digest(source),
                                                  "installed_utc": datetime.now(timezone.utc).isoformat()})
    marketplace = register(home, destination)
    return {"version": version, "release_directory": str(destination), "marketplace": str(marketplace),
            "next_step": "Restart ChatGPT desktop, open Plugins, choose your personal marketplace, install/refresh Secure Firewall Assistant, then start a new local Work chat.",
            "inventory_and_credentials_changed": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rollback", help="Select a previously installed release directory name")
    args = p.parse_args()
    try:
        if args.rollback:
            if not re.fullmatch(r"[0-9A-Za-z.-]+", args.rollback) or ".." in args.rollback:
                raise RuntimeError("Invalid release directory name.")
            destination = Path.home() / ".codex/plugins" / NAME / "releases" / args.rollback
            if not (destination / "installation.json").is_file():
                raise RuntimeError("That release has not completed installation.")
            register(Path.home(), destination)
            result = {"selected_release": str(destination), "next_step": "Restart ChatGPT and refresh/reinstall the plugin from the marketplace."}
        else:
            result = install(Path(__file__).resolve().parents[1])
        print(json.dumps(result, indent=2))
    except Exception:
        print("Installation did not complete. The prior marketplace entry and private enrollment remain available. Check uv output, network access, and the installation guide.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
