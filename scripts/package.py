"""Build reproducible private plugin/source ZIPs using explicit include lists."""
import argparse
import hashlib
import json
import re
import stat
import tomllib
import zipfile
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
TOP = {"plugin.json", "mcp.json", "pyproject.toml", "uv.lock", ".python-version", "README.md",
       "CHANGELOG.md", "CONTRIBUTING.md", "NOTICE.md", "Install.command", "Manage.command", "Install.ps1", "Manage.ps1"}
TOP.add(".mcp.json")
TOP.add("devices.example.yaml")
DIRECTORIES = {"src", "skills", "docs", "scripts", "deployment", ".codex-plugin"}
EXCLUDED_PARTS = {"__pycache__", ".venv", ".pytest_cache", ".ruff_cache"}


def validate(root=ROOT):
    for name in ("plugin", "mcp"):
        schema = json.loads((root / f"scripts/specs/{name}.schema.json").read_text())
        instance = json.loads((root / f"{name}.json").read_text())
        jsonschema.validators.validator_for(schema)(schema).validate(instance)
    plugin = json.loads((root / "plugin.json").read_text())
    interface = plugin["extensions"]["com.openai"]["interface"]
    assert len(interface["shortDescription"]) <= 30
    assert plugin["extensions"]["com.openai"]["requires_local_executor"] is True
    version = plugin["version"]
    compatibility = json.loads((root / ".codex-plugin/plugin.json").read_text())
    assert compatibility["name"] == plugin["name"] and compatibility["version"] == version
    assert compatibility["mcpServers"] == "./.mcp.json"
    portable = json.loads((root / "mcp.json").read_text())["mcpServers"]
    legacy = json.loads((root / ".mcp.json").read_text())["mcpServers"]
    assert legacy == {name: {k: v for k, v in fields.items() if k != "type"}
                      for name, fields in portable.items()}
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?", version)
    assert tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"] == version
    assert f'__version__ = "{version}"' in (root / "src/secure_firewall_assistant/__init__.py").read_text()
    names = []
    for path in (root / "skills").glob("*/SKILL.md"):
        text = path.read_text(encoding="utf-8")
        assert text.startswith("---\n") and len(text.encode()) <= 1024 * 1024
        frontmatter = yaml.safe_load(text.split("---", 2)[1])
        assert frontmatter["name"] == path.parent.name and frontmatter["description"].strip()
        names.append(frontmatter["name"])
    assert names and len(names) == len(set(names))
    for transport in json.loads((root / "mcp.json").read_text())["mcpServers"].values():
        assert transport["type"] == "stdio" and transport["command"] == "uv"
        assert "${PLUGIN_ROOT}" in transport["args"] and "--offline" in transport["args"]
    return version


def selected_files(root=ROOT, source=False):
    chosen = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in rel.parts) or path.is_dir():
            continue
        include = (rel.as_posix() in TOP or rel.parts[0] in DIRECTORIES or
                   (source and (rel.parts[0] in {"tests", ".github", ".agents"} or rel.as_posix() == ".gitignore")))
        if not include:
            continue
        if path.is_symlink():
            raise ValueError("Symlinks are not permitted in release archives")
        if path.suffix == ".pyc" or path.name in {"inventory.json", "installation.json", ".env", "devices.yaml", "devices.yaml.lock"}:
            raise ValueError("Private/generated file appeared in the release include set")
        chosen.append(path)
    return chosen


def build(output: Path, root=ROOT):
    version = validate(root)
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for source in (False, True):
        label = "source" if source else "plugin"
        path = output / f"secure-firewall-assistant-{version}-{label}.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for file in selected_files(root, source):
                rel = file.relative_to(root).as_posix()
                info = zipfile.ZipInfo("secure-firewall-assistant/" + rel, date_time=(2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                mode = 0o755 if file.suffix == ".command" else 0o644
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, file.read_bytes())
        # Inspect the actual output archive, not just the source directory.
        with zipfile.ZipFile(path) as archive:
            assert archive.testzip() is None
            names = archive.namelist()
            assert len(names) == len(set(names)) and all(n.startswith("secure-firewall-assistant/") for n in names)
            assert "secure-firewall-assistant/plugin.json" in names
            assert not any("/.venv/" in n or "/__pycache__/" in n or n.endswith("inventory.json") for n in names)
            assert source or not any("/.agents/" in n or "/.github/" in n or "/tests/" in n for n in names)
        results.append({"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "bytes": path.stat().st_size, "files": len(names)})
    (output / "SHA256SUMS").write_text("".join(f"{r['sha256']}  {r['file']}\n" for r in results))
    (output / "release.json").write_text(json.dumps({"version": version, "artifacts": results}, indent=2) + "\n")
    print(json.dumps({"version": version, "artifacts": results}, indent=2))
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    build(parser.parse_args().output.resolve())
