import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("schema_sync", Path(__file__).resolve().parents[1] / "scripts/sync_schema_repository.py")
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


def snapshot(extra=None, missing=False):
    package = b"synthetic schema bytes"
    checksum = hashlib.sha256(package).hexdigest()
    files = {"runtime/pyproject.toml": b"[project]\nname='fixture'\n",
             "deployment/secure-firewall-schemas.service": b"[Service]\n",
             "registry/index.json": json.dumps({"schemas": [{"sha256": checksum}]}).encode(),
             "registry/revisions.json": json.dumps({"10.5.0.0/r1": checksum}).encode()}
    if not missing:
        files[f"registry/{checksum}.json.gz"] = package
    files.update(extra or {})
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def test_deployed_snapshot_records_exact_bytes_and_removes_obsolete_files(tmp_path):
    (tmp_path / "runtime").mkdir()
    (tmp_path / "runtime/obsolete.py").write_text("old")
    manifest = sync.unpack_snapshot(snapshot(), tmp_path)
    assert not (tmp_path / "runtime/obsolete.py").exists()
    for name, checksum in manifest["files"].items():
        assert hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() == checksum
    assert json.loads((tmp_path / "snapshot.json").read_text()) == manifest
    assert sync.unpack_snapshot(snapshot(), tmp_path) == manifest


@pytest.mark.parametrize("extra,missing", [({"../outside": b"bad"}, False),
                                          ({"unexpected/key": b"bad"}, False), ({}, True)])
def test_invalid_snapshot_never_changes_existing_files(tmp_path, extra, missing):
    (tmp_path / "runtime").mkdir()
    original = tmp_path / "runtime/keep.py"
    original.write_text("preserve")
    with pytest.raises(RuntimeError):
        sync.unpack_snapshot(snapshot(extra, missing), tmp_path)
    assert original.read_text() == "preserve"
