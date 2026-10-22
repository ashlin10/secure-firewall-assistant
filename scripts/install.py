"""Install/update a private local plugin without touching inventory or credentials."""
import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("sfa_runtime", Path(__file__).with_name("runtime.py"))
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
NAME = runtime.NAME
write_json = runtime.write_json


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
    result = runtime.prepare(source, home, uv_binary, runner, allow_downgrade=True, package_root_is_release=True)
    destination = Path(result["release_directory"])
    # Keep the launch root portable: a host-refreshed package bootstraps itself.
    # Only executable discovery is local to this prepared marketplace copy.
    uv_binary = str(Path(uv_binary or shutil.which("uv")).resolve())
    mcp = json.loads((source / "mcp.json").read_text(encoding="utf-8"))
    mcp["mcpServers"]["secure-firewall"]["command"] = uv_binary
    write_json(destination / "mcp.json", mcp)
    legacy = {name: {key: value for key, value in fields.items() if key != "type"}
              for name, fields in mcp["mcpServers"].items()}
    write_json(destination / ".mcp.json", {"mcpServers": legacy})
    marketplace = register(home, destination)
    return {**result, "marketplace": str(marketplace),
            "next_step": "Refresh the plugin and start a new local chat. Restart the desktop host if it retains old tool definitions.",
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
            selected = runtime.prepare(destination, allow_downgrade=True)
            register(Path.home(), destination)
            result = {**selected, "marketplace_release": str(destination),
                      "next_step": "Refresh the plugin and restart the desktop host to complete rollback."}
        else:
            result = install(Path(__file__).resolve().parents[1])
        print(json.dumps(result, indent=2))
    except Exception:
        print("Installation did not complete. The prior marketplace entry and private enrollment remain available. Check uv output, network access, and the installation guide.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
