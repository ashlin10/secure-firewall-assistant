import asyncio
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sfa_runtime_test", ROOT / "scripts/runtime.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def source_at(path, version="1.0.0"):
    path.mkdir(parents=True)
    (path / "plugin.json").write_text(json.dumps({"name": runtime.NAME, "version": version}))
    (path / "pyproject.toml").write_text("[project]\nname='fixture'\n")
    (path / "uv.lock").write_text("fixture lock")
    (path / "scripts").mkdir()
    (path / "scripts/runtime.py").write_bytes((ROOT / "scripts/runtime.py").read_bytes())
    return path


def fake_runner(calls, fail=False):
    def run(command, **options):
        calls.append(command)
        if fail:
            raise subprocess.CalledProcessError(1, command)
        if "sync" in command:
            release = Path(command[command.index("--project") + 1])
            interpreter = runtime.runtime_python(release)
            interpreter.parent.mkdir(parents=True, exist_ok=True)
            interpreter.write_text("fixture executable")
    return run


def test_refresh_activates_new_runtime_and_warm_start_is_offline(tmp_path):
    home = tmp_path / "home"
    first = source_at(tmp_path / "cache/first")
    second = source_at(tmp_path / "cache/second", "1.1.0")
    calls = []
    one = runtime.prepare(first, home, sys.executable, fake_runner(calls))
    two = runtime.prepare(second, home, sys.executable, fake_runner(calls))
    base = home / ".codex/plugins" / runtime.NAME
    assert runtime.active_release(base) == Path(two["release_directory"])
    assert Path(one["release_directory"]).exists()
    calls.clear()
    runtime.prepare(second, home, sys.executable, fake_runner(calls))
    assert calls == []
    # A cached older package must not downgrade the standalone dispatcher.
    runtime.prepare(first, home, sys.executable, fake_runner(calls))
    assert runtime.active_release(base) == Path(two["release_directory"])
    runtime.prepare(first, home, sys.executable, fake_runner(calls), allow_downgrade=True)
    assert runtime.active_release(base) == Path(one["release_directory"])


def test_failed_upgrade_preserves_active_runtime_and_private_data(tmp_path):
    home = tmp_path / "home"
    base = home / ".codex/plugins" / runtime.NAME
    runtime.prepare(source_at(tmp_path / "first"), home, sys.executable, fake_runner([]))
    private = base / "devices.yaml"
    private.write_text("PRIVATE-SENTINEL")
    before = (base / "active.json").read_bytes()
    with pytest.raises(subprocess.CalledProcessError):
        runtime.prepare(source_at(tmp_path / "second", "1.1.0"), home, sys.executable, fake_runner([], fail=True))
    assert (base / "active.json").read_bytes() == before
    assert private.read_text() == "PRIVATE-SENTINEL"


def test_health_check_failure_never_activates_candidate(tmp_path):
    home = tmp_path / "home"
    base = home / ".codex/plugins" / runtime.NAME
    runtime.prepare(source_at(tmp_path / "first"), home, sys.executable, fake_runner([]))
    before = (base / "active.json").read_bytes()
    install = fake_runner([])
    def fail_health(command, **options):
        if command[-1] == 'health':
            raise subprocess.CalledProcessError(1, command)
        install(command, **options)
    with pytest.raises(subprocess.CalledProcessError):
        runtime.prepare(source_at(tmp_path / "second", "1.1.0"), home, sys.executable, fail_health)
    assert (base / 'active.json').read_bytes() == before
    candidate = next(path for path in (base / 'releases').iterdir() if path.name.startswith('1.1.0-'))
    assert not (candidate / 'installation.json').exists()


def test_concurrent_cold_starts_prepare_only_once(tmp_path):
    source = source_at(tmp_path / "source")
    home = tmp_path / "home"
    calls = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: runtime.prepare(source, home, sys.executable, fake_runner(calls)), range(2)))
    assert results[0]["release_directory"] == results[1]["release_directory"]
    assert len(calls) == 2  # One sync and one health check.


@pytest.mark.parametrize("header", ['[mcp_servers.secure-firewall]', '[mcp_servers."secure-firewall"]'])
@pytest.mark.parametrize("newline", ['\n', '\r\n'])
def test_migration_preserves_comments_env_and_custom_policies(tmp_path, header, newline):
    base = tmp_path / ".codex/plugins" / runtime.NAME
    config = tmp_path / ".codex/config.toml"
    config.parent.mkdir(parents=True)
    original = f'''# Keep this comment
model = "fixture"
{header}
command = "uv"
args = [
  "run", "--project", {json.dumps(str(base / "releases/old"))},
  "--offline", "secure-firewall-assistant", "serve",
]
enabled = false
startup_timeout_sec = 120
enabled_tools = ["start_enrollment"]
[mcp_servers.secure-firewall.env]
SFA_DATA_DIR = "private-fixture"
[mcp_servers.other]
command = "preserve-me"
'''
    original = original.replace('\n', newline)
    config.write_bytes(original.encode())
    expected = tomllib.loads(original)
    expected['mcp_servers']['secure-firewall'].update(runtime.stable_transport(base, 'fixture-uv'))
    assert runtime.migrate_registration(tmp_path, base, 'fixture-uv') == 'migrated'
    assert tomllib.loads(config.read_text()) == expected
    assert '# Keep this comment' in config.read_text()
    backup = next(config.parent.glob('config.sfa-backup-*'))
    assert backup.read_bytes() == original.encode()
    if newline == '\r\n':
        assert b'\n' not in config.read_bytes().replace(b'\r\n', b'')
    assert runtime.migrate_registration(tmp_path, base, 'fixture-uv') == 'stable'
    assert len(list(config.parent.glob('config.sfa-backup-*'))) == 1


def test_custom_standalone_server_is_preserved(tmp_path):
    config = tmp_path / '.codex/config.toml'
    config.parent.mkdir()
    config.write_text('[mcp_servers.secure-firewall]\nurl="https://fixture.invalid/mcp"\n')
    before = config.read_bytes()
    assert runtime.migrate_registration(tmp_path, tmp_path, 'uv') == 'custom_registration_preserved'
    assert config.read_bytes() == before


def test_standalone_resolves_installed_version_not_newest_leftover_cache(tmp_path):
    marketplace = tmp_path / '.codex/plugins/cache/team' / runtime.NAME
    selected = source_at(marketplace / '1.1.0', '1.1.0')
    source_at(marketplace / '9.0.0', '9.0.0')
    entry = {'name':runtime.NAME, 'installed':True, 'enabled':True,
             'version':'1.1.0', 'marketplaceName':'team', 'source':{'source':'remote'}}
    def listing(command, **kwargs):
        assert command == ['fixture-codex', 'plugin', 'list', '--json']
        return subprocess.CompletedProcess(command, 0, json.dumps({'installed':[entry]}))
    assert runtime.installed_source(tmp_path, 'fixture-codex', listing) == selected


def test_standalone_refuses_ambiguous_plugin_identities(tmp_path):
    entry = {'name':runtime.NAME, 'installed':True, 'enabled':True}
    def listing(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, json.dumps({'installed':[entry, entry]}))
    with pytest.raises(RuntimeError, match='Multiple enabled'):
        runtime.installed_source(tmp_path, 'fixture-codex', listing)


def test_real_package_refresh_and_stable_dispatcher_over_stdio(tmp_path):
    uv = shutil.which('uv')
    if not uv:
        pytest.skip('uv is required for real runtime upgrade validation')
    home = tmp_path / 'isolated home'
    source = tmp_path / 'plugin cache with spaces'
    for path, relative in runtime.selected_files(ROOT):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    environment = {**os.environ, 'SFA_DATA_DIR': str(tmp_path / 'private')}

    async def health(command, args):
        async with Client(StdioServerParameters(command=command, args=args, env=environment),
                          read_timeout_seconds=180) as client:
            assert len((await client.list_tools()).tools) == 19
            result = await client.call_tool('assistant_health')
            value = result.structured_content or json.loads(result.content[0].text)
            enrollment = await client.call_tool('start_enrollment')
            assert enrollment.structured_content['devices'] == []
            resource = await client.read_resource('ui://secure-firewall/add-devices/v1.html')
            assert 'const enrollmentOnly=true;' in resource.contents[0].text
            return value['version']

    async def run():
        args = ['run', '--no-project', '--python', '3.12', str(source / 'scripts/runtime.py'),
                '--source', str(source), '--runtime-home', str(home)]
        first = await health(uv, args)
        base = home / '.codex/plugins' / runtime.NAME
        before = runtime.active_release(base)
        # Simulate changed files delivered to an installed plugin cache, with no
        # installer invocation, prebuilt venv, or standalone registration changes.
        service = source / 'src/secure_firewall_assistant/service.py'
        service.write_text(service.read_text().replace('"version": __version__', '"version": "updated-fixture"'))
        bootstrap = source / 'scripts/runtime.py'
        bootstrap.write_text(bootstrap.read_text() + '\n# refreshed bootstrap fixture\n')
        transport = runtime.stable_transport(base, uv)
        # The stable registration upgrades even before the bundled MCP starts.
        assert await health(transport['command'], transport['args']) == 'updated-fixture'
        assert runtime.active_release(base) != before
        assert (base / 'launcher.py').read_bytes() == bootstrap.read_bytes()
        assert before.exists()
        # Remove the package cache: the standalone dispatcher uses its durable runtime.
        shutil.rmtree(source)
        assert await health(transport['command'], transport['args']) == 'updated-fixture'
        assert first != 'updated-fixture'
    asyncio.run(run())
