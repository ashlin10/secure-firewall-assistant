import importlib.util
import zipfile
from pathlib import Path

import pytest

from secure_firewall_assistant import __version__

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sfa_package", ROOT / "scripts/package.py")
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


def test_archives_are_valid_scoped_and_reproducible(tmp_path):
    first = packager.build(tmp_path / "a")
    second = packager.build(tmp_path / "b")
    assert [r["sha256"] for r in first] == [r["sha256"] for r in second]
    with zipfile.ZipFile(tmp_path / "a" / first[0]["file"]) as archive:
        names = archive.namelist()
        assert not any("/tests/" in n or "/.agents/" in n for n in names)
        assert not any('/deployment/' in n or n.endswith(('push_repositories.py', 'sync_schema_repository.py', 'REPOSITORIES.md')) for n in names)
        for name in names:
            assert b'aleroyds' not in archive.read(name)
        assert b'http://10.196.150.41:8765/mcp' in archive.read(
            'secure-firewall-assistant/src/secure_firewall_assistant/schema_registry.py')
        assert "secure-firewall-assistant/Install.ps1" in names
        assert "secure-firewall-assistant/Install.command" in names
        assert archive.getinfo("secure-firewall-assistant/Install.command").external_attr >> 16 & 0o111


def test_native_manifests_and_skill_validate():
    assert packager.validate() == __version__


def test_export_rejects_personal_paths_and_private_settings(tmp_path):
    (tmp_path / 'src').mkdir()
    marker = tmp_path / 'src/settings.json'
    marker.write_text('{"path":"/Users/someone/private/runtime"}')
    with pytest.raises(ValueError, match='Machine-specific'):
        packager.selected_files(tmp_path)
    marker.unlink()
    (tmp_path / 'scripts').mkdir()
    (tmp_path / 'scripts/schema-service.json').write_text('{"url":"https://private.example/mcp"}')
    with pytest.raises(ValueError, match='Private/generated'):
        packager.selected_files(tmp_path)
