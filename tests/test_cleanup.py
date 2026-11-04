import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('cleanup', Path(__file__).resolve().parents[1] / 'scripts/cleanup_releases.py')
cleanup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cleanup)


def setup(home):
    base = home / '.codex/plugins/secure-firewall-assistant'
    active = base / 'releases/1.1.0-aaaaaaaaaaaa'
    old = base / 'releases/1.0.0-bbbbbbbbbbbb'
    cache = home / '.codex/plugins/cache/personal-local/secure-firewall-assistant/1.0.0'
    for path, version in [(active, '1.1.0'), (old, '1.0.0'), (cache, '1.0.0')]:
        path.mkdir(parents=True)
        (path / 'plugin.json').write_text(json.dumps({'name': cleanup.runtime.NAME, 'version': version}))
    executable = cleanup.runtime.runtime_python(active)
    executable.parent.mkdir(parents=True)
    executable.touch()
    marker = {'version': '1.1.0', 'source_sha256': 'fixture'}
    (active / 'installation.json').write_text(json.dumps(marker))
    (base / 'active.json').write_text(json.dumps({**marker, 'release_directory': str(active)}))
    private = base / 'devices.yaml'
    private.write_text('private sentinel')
    return active, old, cache, private


def test_cleanup_keeps_active_and_private_data(tmp_path, monkeypatch):
    active, old, cache, private = setup(tmp_path)
    monkeypatch.setattr(cleanup.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess([], 0, ''))
    result = cleanup.cleanup(tmp_path)
    assert len(result['removed']) == 2
    assert active.exists() and not old.exists() and not cache.exists()
    assert private.read_text() == 'private sentinel'


def test_cleanup_refuses_running_old_runtime_before_deleting_anything(tmp_path, monkeypatch):
    active, old, cache, private = setup(tmp_path)
    monkeypatch.setattr(cleanup.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess([], 0, str(old / '.venv/bin/python')))
    with pytest.raises(RuntimeError, match='running'):
        cleanup.cleanup(tmp_path)
    assert active.exists() and old.exists() and cache.exists() and private.exists()
