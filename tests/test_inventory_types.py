import json

import pytest
import yaml

from secure_firewall_assistant.enrollment_ui import EnrollmentUI
from secure_firewall_assistant.errors import AssistantError
from secure_firewall_assistant.inventory import DEVICE_TYPES, normalize_inventory


def test_all_types_and_type_move_preserve_credentials(assistant, lab):
    ui = EnrollmentUI(assistant.state, assistant.secrets)
    rows = [{'device_name':'device-'+kind, 'device_type':kind, 'hostname':'fixture.example.invalid',
             'https_port':443,'ssh_port':22,'username':'fixture','password':'SYNTHETIC-'+kind} for kind in DEVICE_TYPES]
    result = ui.save(rows)
    saved = yaml.safe_load(assistant.state.device_file.read_text())
    assert saved['format_version'] == 3
    assert set(DEVICE_TYPES) <= set(saved['devices'])
    assert set(saved) == {'format_version', 'devices'}
    for kind in DEVICE_TYPES:
        alias = 'device-'+kind
        assert alias in [r['device_name'] for r in saved['devices'][kind]]
        assert assistant.state.device(alias).kind == kind
        assert assistant.secrets.get(alias+'-auth') == 'SYNTHETIC-'+kind
    assert 'SYNTHETIC-' not in json.dumps(result)
    ui.save([{**rows[0], 'device_type':'routers','password':''}])
    saved = yaml.safe_load(assistant.state.device_file.read_text())
    assert not any(r['device_name'] == 'device-fmc' for r in saved['devices']['fmc'])
    assert any(r['device_name'] == 'device-fmc' for r in saved['devices']['routers'])
    assert assistant.secrets.get('device-fmc-auth') == 'SYNTHETIC-fmc'
    assert assistant.state.device('device-fmc').address == 'fixture.example.invalid'
    with pytest.raises(AssistantError, match='FMC'):
        assistant.client('device-routers')
    assert lab.calls == []


def test_legacy_migration_preserves_all_accounts_and_api_secrets(assistant):
    store = assistant.secrets
    store.path.write_text(yaml.safe_dump({'format_version':1, 'devices':{'legacy':{
        'device_name':'legacy','hostname':'fixture.invalid','https_port':443,'ssh_port':22,
        'username':'fixture','password':'SYNTHETIC-LEGACY'}},'secrets':{'vpn':'SYNTHETIC-VPN'}}))
    with __import__('filelock').FileLock(str(store.path)+'.lock'):
        store._write(store._read())
    saved = yaml.safe_load(store.path.read_text())
    assert saved['devices']['fmc'][0]['device_name'] == 'legacy'
    assert store.get('legacy-auth') == 'SYNTHETIC-LEGACY'
    assert store.get('vpn') == 'SYNTHETIC-VPN'
    assert store.path.with_name('.sfa-devices-pre-grouped.backup').exists()
    assert assistant.state.inventory()['devices']['legacy']['kind'] == 'fmc'


def test_invalid_grouping_and_unknown_type_rejected():
    for value in ({'format_version':2,'fmc':{'same':{}},'ftd':{'same':{}}},
                  {'format_version':2,'fmc':{'device':{'kind':'ftd'}}},
                  {'format_version':2,'unknown':{}},
                  {'format_version':2,'fmc':[]}):
        with pytest.raises(ValueError):
            normalize_inventory(value)


def test_format_two_remains_readable():
    old = {'format_version': 2, 'ftd': {'old': {'hostname': 'fixture.invalid'}}}
    result = normalize_inventory(old)
    assert result['devices']['old']['kind'] == 'ftd'


def test_protocol_accounts_select_correct_login_and_preserve_other_password(assistant, lab):
    ui = EnrollmentUI(assistant.state, assistant.secrets)
    accounts = dict(ssh_username='ssh-fixture', ssh_password='SYNTHETIC-SSH',
                    https_username='api-fixture', https_password='SYNTHETIC-HTTPS')
    base = dict(hostname='fixture.invalid', https_port=443, ssh_port=2222)
    ui.save([{**base, **accounts, 'device_name':'split-fmc', 'device_type':'fmc'},
             {**base, **accounts, 'device_name':'split-ftd', 'device_type':'ftd'}])
    assert assistant.state.device('split-fmc').username == 'api-fixture'
    assert assistant.state.device('split-ftd').username == 'ssh-fixture'
    assert assistant.secrets.get('split-fmc-auth') == 'SYNTHETIC-HTTPS'
    assert assistant.secrets.get('split-ftd-auth') == 'SYNTHETIC-SSH'
    assert assistant.secrets.get('split-fmc-auth', protocol='ssh') == 'SYNTHETIC-SSH'
    assert assistant.secrets.get('split-ftd-auth', protocol='https') == 'SYNTHETIC-HTTPS'
    ui.save([{**base, **accounts, 'device_name':'split-fmc', 'device_type':'fmc',
              'ssh_password':'', 'https_password':'SYNTHETIC-ROTATED-HTTPS'}])
    assert assistant.secrets.get('split-fmc-auth', protocol='ssh') == 'SYNTHETIC-SSH'
    assert assistant.secrets.get('split-fmc-auth') == 'SYNTHETIC-ROTATED-HTTPS'
    public = json.dumps(ui.start().model_dump())
    assert 'SYNTHETIC-' not in public
    saved = assistant.secrets._read()['devices']['split-fmc']
    assert 'username' not in saved and 'password' not in saved
    assert lab.calls == []


def test_migration_copies_shared_account_to_both_protocols(assistant):
    store = assistant.secrets
    store.path.write_text(yaml.safe_dump({'format_version':3, 'devices':{'switches':[{
        'device_name':'legacy-switch', 'hostname':'switch.invalid', 'https_port':443,
        'ssh_port':2222, 'username':'legacy-user', 'password':'SYNTHETIC-SHARED'}]}}))
    store._write(store._read())
    record = store._read()['devices']['legacy-switch']
    for protocol in ('ssh', 'https'):
        assert record[protocol + '_username'] == 'legacy-user'
        assert record[protocol + '_password'] == 'SYNTHETIC-SHARED'
    assert 'username' not in record and 'password' not in record
    assert assistant.state.device('legacy-switch').username == 'legacy-user'


@pytest.mark.parametrize('sections', [
    {'unknown': []}, {'fmc': {}}, {'fmc': [None]},
    {'fmc': [{'device_name': 'same'}], 'ftd': [{'device_name': 'same'}]},
    {'fmc': [{'device_name': 'bad', 'kind': 'ftd'}]},
])
def test_invalid_nested_sections(sections):
    with pytest.raises(ValueError):
        normalize_inventory({'format_version': 3, 'devices': sections})
