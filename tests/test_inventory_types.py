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
    assert saved['format_version'] == 2
    assert set(DEVICE_TYPES) <= set(saved)
    assert 'devices' not in saved
    for kind in DEVICE_TYPES:
        alias = 'device-'+kind
        assert alias in saved[kind]
        assert assistant.state.device(alias).kind == kind
        assert assistant.secrets.get(alias+'-auth') == 'SYNTHETIC-'+kind
    assert 'SYNTHETIC-' not in json.dumps(result)
    ui.save([{**rows[0], 'device_type':'routers','password':''}])
    saved = yaml.safe_load(assistant.state.device_file.read_text())
    assert 'device-fmc' not in saved['fmc'] and 'device-fmc' in saved['routers']
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
    assert 'legacy' in saved['fmc']
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
