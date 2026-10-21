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
    before = assistant.secrets._read()
    config_before = assistant.state.inventory_path.read_bytes()
    ui.save([row(), row('lab-fmc-1', 'fmc.example.invalid')])
    saved = yaml.safe_load(assistant.state.device_file.read_text())
    assert saved['credentials'] == before['credentials']
    assert saved['devices']['new-device'] == row()
    assert assistant.state.inventory_path.read_bytes() == config_before
    assert assistant.state.inventory()['devices']['new-device']['address'] == 'https://[2001:db8::1]:12202'
    assert ui.rows() == [row('lab-fmc-1', 'fmc.example.invalid'), row()]
    assert lab.calls == []
    ui.save([row(https=443)])
    assert len(ui.rows()) == 2
    assert assistant.secrets._read()['credentials'] == before['credentials']
    with pytest.raises(AssistantError, match='local account'):
        assistant.state.device('new-device')


@pytest.mark.parametrize('devices', [
    [row(https=0)], [row(ssh=65536)], [row(https=True)], [row(ssh=22.5)],
    [row(host='https://example.invalid')], [row(host='host:443')], [row(host='bad host')],
    [row(name='../escape')], [row(), row()], [row(), row(host='bad/host')], [],
    [{**row(), 'password': 'forbidden'}],
])
def test_invalid_inventory_never_writes(assistant, devices):
    before = assistant.state.device_file.read_bytes()
    with pytest.raises(AssistantError):
        EnrollmentUI(assistant.state, assistant.secrets).save(devices)
    assert assistant.state.device_file.read_bytes() == before


def test_existing_device_settings_are_preserved(assistant):
    device = assistant.state.inventory()['devices']['lab-fmc-1']
    ui = EnrollmentUI(assistant.state, assistant.secrets)
    ui.save([row('lab-fmc-1', 'changed.example.invalid', 8443, 2222)])
    updated = assistant.state.device('lab-fmc-1')
    assert updated.username == device['username']
    assert updated.domain == device['domain']
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
            for absent in ('Check local connection', 'type="password"', 'fetch(', 'connect_fmc', '/probe', 'Username'):
                assert absent not in html
            result = await client.call_tool('start_enrollment', {'alias':'fixture','address':'https://example.invalid:8443'})
            public = json.loads(result.content[0].text)
            assert public['status'] == 'edit_device_inventory'
            assert public['devices'][-1] == row('fixture', 'example.invalid', 8443, 22)
            result = await client.call_tool('save_device_inventory', {'devices':[row()]})
            assert 'inventory_saved' in result.content[0].text
            assert lab.calls == []
    asyncio.run(run())


def test_card_bridge_flow():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node needed for component test')
    root = Path(__file__).resolve().parents[1]
    subprocess.run([node, str(root / 'tests/card_flow.mjs'),
                    str(root / 'src/secure_firewall_assistant/enrollment_card.html')], check=True)
