import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from mcp import Client

from secure_firewall_assistant.enrollment_ui import MIME, EnrollmentUI
from secure_firewall_assistant.errors import AssistantError
from secure_firewall_assistant.server import build_server


def row(name='new-device', host='2001:db8::1', https=12202, ssh=2222):
    return dict(device_name=name, hostname=host, https_port=https, ssh_port=ssh)


def test_inventory_only_save_and_readback_preserves_credentials(assistant, lab):
    ui = EnrollmentUI(assistant.state, assistant.secrets)
    config_before = assistant.state.inventory_path.read_bytes()
    ui.save([row(), row('lab-fmc-1', 'fmc.example.invalid')])
    saved = yaml.safe_load(assistant.state.device_file.read_text())
    assert 'credentials' not in saved
    assert next(r for r in saved['devices']['fmc'] if r['device_name'] == 'lab-fmc-1')['https_password'] == 'SYNTHETIC-LOGIN-SENTINEL'
    assert next(r for r in saved['devices']['fmc'] if r['device_name'] == 'new-device') == {**row(), 'ssh_username':'', 'ssh_password':'', 'https_username':'', 'https_password':''}
    assert assistant.state.inventory_path.read_bytes() == config_before
    assert assistant.state.inventory()['devices']['new-device']['address'] == 'https://[2001:db8::1]:12202'
    assert [r['device_name'] for r in ui.rows()] == ['lab-fmc-1', 'new-device']
    assert 'SYNTHETIC-LOGIN' not in json.dumps(ui.start().model_dump())
    assert lab.calls == []
    ui.save([row(https=443)])
    assert len(ui.rows()) == 2
    assert assistant.secrets.get('lab-fmc-1-auth') == 'SYNTHETIC-LOGIN-SENTINEL'
    with pytest.raises(AssistantError, match='local account'):
        assistant.state.device('new-device')


@pytest.mark.parametrize('devices', [
    [row(https=0)], [row(ssh=65536)], [row(https=True)], [row(ssh=22.5)],
    [row(host='https://example.invalid')], [row(host='host:443')], [row(host='bad host')],
    [row(name='../escape')], [row(), row()], [row(), row(host='bad/host')],
    [{**row(), 'password': 'forbidden'}],
])
def test_invalid_inventory_never_writes(assistant, devices):
    before = assistant.state.device_file.read_bytes()
    with pytest.raises(AssistantError):
        EnrollmentUI(assistant.state, assistant.secrets).save(devices)
    assert assistant.state.device_file.read_bytes() == before


def test_existing_device_settings_are_preserved(assistant):
    from dataclasses import replace

    assistant.state.save_device(replace(assistant.state.device("lab-fmc-1"), verify_ssl=True))
    device = assistant.state.inventory()['devices']['lab-fmc-1']
    ui = EnrollmentUI(assistant.state, assistant.secrets)
    ui.save([row('lab-fmc-1', 'changed.example.invalid', 8443, 2222)])
    updated = assistant.state.device('lab-fmc-1')
    assert updated.username == device['username']
    assert updated.domain == device['domain']
    assert updated.verify_ssl is True
    assert updated.credential_ref == device['credential_ref']
    assert updated.address == 'https://changed.example.invalid:8443'
    assert updated.port == 2222


def test_mcp_inventory_roundtrip_without_device_connections(assistant, lab):
    async def run():
        async with Client(build_server(assistant)) as client:
            tools = (await client.list_tools()).tools
            descriptor = next(t for t in tools if t.name == 'device_inventory').model_dump(by_alias=True)
            resource = (await client.read_resource(descriptor['_meta']['ui']['resourceUri'])).contents[0].model_dump(by_alias=True)
            assert resource['mimeType'] == MIME
            assert resource['_meta']['ui']['csp']['connectDomains'] == []
            html = resource['text']
            for absent in ('Check local connection', 'type="password"', 'fetch(', 'connect_fmc', '/probe'):
                assert absent not in html
            assert "['ssh_password','SSH password','password','']" in html
            assert 'Delete device' in html
            saver = next(t for t in tools if t.name == 'save_device_inventory')
            assert saver.meta['ui']['visibility'] == ['app']
            result = await client.call_tool('start_enrollment', {'alias':'fixture','address':'https://example.invalid:8443'})
            public = json.loads(result.content[0].text)
            assert public['status'] == 'enroll_devices'
            assert len(public['devices']) == 1
            assert public['devices'][-1] == {**row('fixture', 'example.invalid', 8443, 22), 'ssh_username':'', 'https_username':'', 'has_account':False, 'has_ssh_account':False, 'has_https_account':False, 'device_type':'fmc'}
            result = await client.call_tool('save_device_inventory', {'devices':[row()]})
            assert 'inventory_saved' in result.content[0].text
            assert lab.calls == []
    asyncio.run(run())


@pytest.mark.parametrize('mode', ['inventory', 'enrollment'])
def test_card_bridge_flow(mode):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node needed for component test')
    root = Path(__file__).resolve().parents[1]
    subprocess.run([node, str(root / 'tests/card_flow.mjs'),
                    str(root / 'src/secure_firewall_assistant/enrollment_card.html'), mode], check=True)


def test_new_enrollment_hides_inventory_and_only_adds(assistant, lab):
    ui = EnrollmentUI(assistant.state, assistant.secrets)
    assert ui.start(new_only=True).structured_content['devices'] == []
    before = assistant.state.device('lab-fmc-1')
    result = ui.save([row()], new_only=True)
    assert result['devices'] == [{'device_name': 'new-device'}]
    assert 'lab-fmc-1' not in json.dumps(result)
    assert assistant.state.device('lab-fmc-1') == before
    assert ui.start(new_only=True).structured_content['devices'] == []
    assert lab.calls == []


@pytest.mark.parametrize('devices,deleted', [
    ([row('lab-fmc-1')], []), ([row(), row('lab-fmc-1')], []),
    ([row()], ['lab-fmc-1']), ([], []),
])
def test_new_enrollment_rejects_collisions_and_deletions_without_writing(assistant, devices, deleted):
    before = assistant.state.device_file.read_bytes()
    with pytest.raises(AssistantError):
        EnrollmentUI(assistant.state, assistant.secrets).save(devices, deleted, new_only=True)
    assert assistant.state.device_file.read_bytes() == before


def test_new_enrollment_rechecks_names_after_form_open(assistant):
    ui = EnrollmentUI(assistant.state, assistant.secrets)
    ui.start(new_only=True)
    ui.save([row()], new_only=True)
    before = assistant.state.device_file.read_bytes()
    with pytest.raises(AssistantError, match='already enrolled'):
        ui.save([row(host='changed.invalid')], new_only=True)
    assert assistant.state.device_file.read_bytes() == before


def test_password_save_preserve_rotate_and_response_privacy(assistant, lab):
    ui = EnrollmentUI(assistant.state, assistant.secrets)
    account = {**row(), 'username': 'fixture-user', 'password': '  SYNTHETIC-INLINE  '}
    result = ui.save([account])
    assert assistant.state.device('new-device').username == 'fixture-user'
    assert assistant.secrets.get('new-device-auth') == account['password']
    assert 'SYNTHETIC' not in json.dumps(result)
    assert 'password' not in ui.rows()[-1]
    ui.save([{**account, 'password': ''}])
    assert assistant.secrets.get('new-device-auth') == account['password']
    ui.save([{**account, 'password': 'SYNTHETIC-ROTATED'}])
    assert assistant.secrets.get('new-device-auth') == 'SYNTHETIC-ROTATED'
    assert lab.calls == []


def test_delete_removes_legacy_account_and_supports_empty_inventory(assistant, lab):
    ui = EnrollmentUI(assistant.state, assistant.secrets)
    ui.save([row()])
    ui.save([], ['lab-fmc-1', 'new-device'])
    assert ui.rows() == []
    assert assistant.state.aliases() == []
    saved = assistant.secrets._read()
    assert saved['devices'] == {}
    assert 'SYNTHETIC-LOGIN' not in json.dumps(saved)
    assert json.loads(assistant.state.inventory_path.read_text())['devices'] == {}
    assert lab.calls == []


def test_legacy_credentials_migrate_without_losing_api_secrets(assistant):
    store = assistant.secrets
    store.path.write_text(yaml.safe_dump({'format_version':1, 'devices':{},
        'credentials':{'lab-fmc-1-auth':'SYNTHETIC-LEGACY', 'radius-ref':'SYNTHETIC-RADIUS'}}))
    ui = EnrollmentUI(assistant.state, store)
    ui.save([row('lab-fmc-1', 'fmc.example.invalid')])
    saved = store._read()
    assert 'credentials' not in saved
    assert saved['devices']['lab-fmc-1']['https_password'] == 'SYNTHETIC-LEGACY'
    assert store.get('radius-ref') == 'SYNTHETIC-RADIUS'
    assert store.get('lab-fmc-1-auth') == 'SYNTHETIC-LEGACY'
    assert 'SYNTHETIC' not in json.dumps(ui.start().model_dump())


@pytest.mark.parametrize('deleted', [['../bad'], 'lab-fmc-1', ['new-device']])
def test_invalid_deletions_never_write(assistant, deleted):
    before = assistant.state.device_file.read_bytes()
    with pytest.raises(AssistantError):
        EnrollmentUI(assistant.state, assistant.secrets).save([row()], deleted)
    assert assistant.state.device_file.read_bytes() == before


def test_failed_yaml_delete_restores_legacy_inventory(assistant, monkeypatch):
    before = assistant.state.inventory_path.read_bytes()
    def fail(_):
        raise OSError('synthetic write failure')
    monkeypatch.setattr(assistant.secrets, '_write', fail)
    with pytest.raises(OSError):
        EnrollmentUI(assistant.state, assistant.secrets).save([], ['lab-fmc-1'])
    assert assistant.state.inventory_path.read_bytes() == before
    assert assistant.state.device('lab-fmc-1').username == 'fixture-user'
