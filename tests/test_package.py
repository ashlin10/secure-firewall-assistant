import importlib.util
import zipfile
from pathlib import Path

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
        assert "secure-firewall-assistant/Install.ps1" in names
        assert "secure-firewall-assistant/Install.command" in names
        assert archive.getinfo("secure-firewall-assistant/Install.command").external_attr >> 16 & 0o111


def test_native_manifests_and_skill_validate():
    assert packager.validate() == "0.1.0"
