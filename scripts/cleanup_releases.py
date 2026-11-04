"""Keep only the active verified local release/cache and current packaged archives.

Never removes inventory, credentials, evidence, configuration backups, Git history,
or published schema history. Stop old MCP processes before running cleanup.
"""
import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("sfa_runtime", Path(__file__).with_name("runtime.py"))
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def cleanup(home=None):
    home = (home or Path.home()).resolve()
    base = home / ".codex/plugins" / runtime.NAME
    with runtime.runtime_lock(base):
        active = runtime.active_release(base)
        state = json.loads((base / "active.json").read_text())
        version = state["version"]
        current = tuple(map(int, version.split(".")))
        candidates = []
        roots = [base / "releases"]
        cache = home / ".codex/plugins/cache"
        if cache.exists():
            roots.extend(p / runtime.NAME for p in cache.iterdir() if p.is_dir() and not p.is_symlink())
        for root in roots:
            if not root.is_dir() or root.is_symlink():
                continue
            for path in root.iterdir():
                if path.is_symlink() or not path.is_dir() or path.resolve() == active:
                    continue
                match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-[0-9a-f]{12})?", path.name)
                if not match or (root != base / "releases" and match[1] == version):
                    continue
                if tuple(map(int, match[1].split("."))) > current:
                    raise RuntimeError("A newer installed version exists; activate it before cleanup")
                manifest = json.loads((path / "plugin.json").read_text())
                if manifest.get("name") != runtime.NAME or manifest.get("version") != match[1]:
                    raise RuntimeError("Unexpected release identity; cleanup stopped")
                candidates.append(path)
        if candidates:
            # Fail before deleting anything when process inspection is unavailable.
            if os.name == "nt":
                result = subprocess.run(["powershell", "-NoProfile", "-Command",
                    "Get-CimInstance Win32_Process | Select-Object -ExpandProperty CommandLine"],
                    check=True, capture_output=True, text=True)
            else:
                result = subprocess.run(["ps", "-axo", "command="], check=True, capture_output=True, text=True)
            for path in candidates:
                if str(path) in result.stdout:
                    raise RuntimeError(f"Old runtime is running: {path.name}. Restart the desktop host and rerun cleanup.")
            for path in candidates:
                shutil.rmtree(path)
        return {"kept_version": version, "kept_release": str(active),
                "removed": [str(p) for p in candidates]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(cleanup(), indent=2))
