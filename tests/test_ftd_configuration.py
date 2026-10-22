import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from secure_firewall_assistant import ssh
from secure_firewall_assistant.errors import AssistantError


@pytest.fixture
def ftd_session(assistant, monkeypatch):
    responses = iter(['> ', 'Manager successfully configured.\r\n> ', 'Registration pending\r\n> '])
    sent = []
    client = SimpleNamespace(
        set_missing_host_key_policy=lambda policy: None,
        connect=lambda *args, **kwargs: None,
        invoke_shell=lambda **kwargs: SimpleNamespace(send=sent.append),
        close=lambda: None,
    )
    device = SimpleNamespace(address='192.0.2.20', port=22, username='user', credential_ref='ftd-login')
    state = SimpleNamespace(device=lambda target, kind: device, target_lock=lambda target: nullcontext())
    assistant.secrets.set('ftd-login', 'SYNTHETIC-LOGIN')
    assistant.secrets.set('registration', 'SYNTHETIC-REGISTRATION')
    monkeypatch.setattr(ssh.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh, 'receive', lambda channel, **kwargs: next(responses))
    return state, assistant.secrets, sent


def test_manager_configuration_resolves_and_redacts_secret(ftd_session, assistant):
    state, secrets, sent = ftd_session
    result = ssh.configuration(state, secrets, 'ftd', 'Register ftd to fmc',
                               [['configure', 'manager', 'add', '192.0.2.10', {'$secret': 'registration'}]],
                               ['show managers'])
    assert sent == ['configure manager add 192.0.2.10 SYNTHETIC-REGISTRATION\n', 'show managers\n']
    assert result['ok'] is True
    assert result['verification_status'] == 'observed'
    assert result['configuration_attempted'] is True
    saved = assistant.evidence.save({'result': result})
    assert 'SYNTHETIC' not in json.dumps(saved)
    assert 'Registration pending' in result['verification_commands'][0]['output']


@pytest.mark.parametrize('tokens', [
    ['expert'], ['configure', 'hostname', 'x\nreboot'],
    ['configure', 'hostname', '$(id)'], ['configure', 'hostname', 'x;reboot'],
    ['configure', 'manager', 'add', '192.0.2.10', 'literal-key'],
])
def test_configuration_rejects_escapes_and_literal_registration_keys(ftd_session, tokens):
    state, secrets, sent = ftd_session
    with pytest.raises(AssistantError):
        ssh.configuration(state, secrets, 'ftd', 'Configure ftd', [tokens], ['show managers'])
    assert not sent


def test_configuration_requires_authorization_and_verification(ftd_session):
    state, secrets, sent = ftd_session
    for request, verification in [('', ['show network']), ('Configure ftd', [])]:
        with pytest.raises(AssistantError):
            ssh.configuration(state, secrets, 'ftd', request, [['configure', 'hostname', 'lab']], verification)
    assert not sent


def test_configuration_never_targets_fmc(assistant):
    with pytest.raises(AssistantError) as error:
        ssh.configuration(assistant.state, assistant.secrets, 'lab-fmc-1', 'Configure FMC',
                          [['configure', 'hostname', 'lab']], ['show network'])
    assert error.value.code == 'wrong_target_kind'


@pytest.mark.parametrize('failure', ['timeout', 'cli'])
def test_configuration_retains_partial_outcome_and_does_not_replay(ftd_session, monkeypatch, failure):
    state, secrets, sent = ftd_session
    outputs = iter(['> ', 'hostname configured\r\n> '])

    def receive(channel, **kwargs):
        try:
            return next(outputs)
        except StopIteration:
            if failure == 'timeout':
                raise AssistantError('ssh_prompt_timeout', 'Prompt timeout')
            return 'Error: rejected\r\n> '

    monkeypatch.setattr(ssh, 'receive', receive)
    result = ssh.configuration(state, secrets, 'ftd', 'Configure ftd',
                               [['configure', 'hostname', 'first'], ['configure', 'hostname', 'second'],
                                ['configure', 'hostname', 'third']], ['show network'])
    assert sent == ['configure hostname first\n', 'configure hostname second\n']
    assert result['ok'] is False
    assert result['configuration_may_have_changed'] is True
    assert len(result['commands']) == 2
    assert result['verification_status'] == 'not_observed'
    assert result['error']['code'] == ('ssh_prompt_timeout' if failure == 'timeout' else 'ftd_cli_error')
