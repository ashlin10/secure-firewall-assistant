import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sfa_installer", ROOT / "scripts/install.py")
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def prepare_source(tmp_path, version="0.1.0"):
    source = tmp_path / ("source-" + version)
    source.mkdir()
    manifest = json.loads((ROOT / "plugin.json").read_text())
    manifest["version"] = version
    (source / "plugin.json").write_text(json.dumps(manifest))
    (source / "mcp.json").write_bytes((ROOT / "mcp.json").read_bytes())
    (source / "uv.lock").write_text("fixture lockfile")
    return source


def test_install_upgrade_preserves_catalog_and_private_files(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    marketplace = home / ".agents/plugins/marketplace.json"
    marketplace.parent.mkdir(parents=True)
    existing = {"name": "my-marketplace", "plugins": [{"name": "other", "source": "./other"}]}
    marketplace.write_text(json.dumps(existing))
    private = home / "private-inventory"
    private.write_text("PRIVATE-INVENTORY-SENTINEL")
    calls = []

    def runner(*args, **kwargs):
        calls.append((args, kwargs))

    first = installer.install(prepare_source(tmp_path), home=home, uv_binary="/fixture/uv", runner=runner)
    second = installer.install(prepare_source(tmp_path, "0.2.0"), home=home, uv_binary="/fixture/uv", runner=runner)
    catalog = json.loads(marketplace.read_text())
    assert catalog["name"] == "my-marketplace"
    assert catalog["plugins"][0] == existing["plugins"][0]
    assert len(catalog["plugins"]) == 2
    assert "0.2.0" in catalog["plugins"][1]["source"]["path"]
    assert Path(first["release_directory"]).exists()
    assert Path(second["release_directory"]).exists()
    assert private.read_text() == "PRIVATE-INVENTORY-SENTINEL"
    transport = json.loads((Path(second["release_directory"]) / "mcp.json").read_text())["mcpServers"]["secure-firewall"]
    assert transport["command"] == str(Path("/fixture/uv").resolve())
    assert second["release_directory"] in transport["args"]
    legacy = json.loads((Path(second["release_directory"]) / ".mcp.json").read_text())["mcpServers"]["secure-firewall"]
    assert legacy == {k: v for k, v in transport.items() if k != "type"}
    assert len(list(marketplace.parent.glob("marketplace.backup-*"))) == 2
    assert len(calls) == 4


def test_dependency_failure_does_not_change_marketplace(tmp_path):
    home = tmp_path / "home"
    marketplace = home / ".agents/plugins/marketplace.json"
    marketplace.parent.mkdir(parents=True)
    marketplace.write_text('{"name":"old","plugins":[]}')
    before = marketplace.read_bytes()

    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ["fixture"])

    with pytest.raises(subprocess.CalledProcessError):
        installer.install(prepare_source(tmp_path), home=home, uv_binary="/fixture/uv", runner=fail)
    assert marketplace.read_bytes() == before


def test_invalid_marketplace_is_not_replaced(tmp_path):
    home = tmp_path / "home"
    marketplace = home / ".agents/plugins/marketplace.json"
    marketplace.parent.mkdir(parents=True)
    marketplace.write_text("invalid-json")
    with pytest.raises(ValueError):
        installer.register(home, home / ".codex/plugins/example")
    assert marketplace.read_text() == "invalid-json"


def test_installer_excludes_venv_and_private_artifacts(tmp_path):
    source = prepare_source(tmp_path)
    (source / ".venv").mkdir()
    (source / ".venv/marker").write_text("excluded")
    result = installer.install(source, home=tmp_path / "home", uv_binary="/fixture/uv", runner=lambda *a, **k: None)
    assert not (Path(result["release_directory"]) / ".venv").exists()
