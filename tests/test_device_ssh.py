import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
import yaml

from secure_firewall_assistant import device_ssh
from secure_firewall_assistant.errors import AssistantError
from secure_firewall_assistant.state import State


class Channel:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.sent = []
        self.closed = False

    def recv_ready(self):
        return bool(self.outputs)

    def recv(self, size):
        return self.outputs.pop(0)

    def sendall(self, value):
        self.sent.append(value)

    def close(self):
        self.closed = True


@pytest.fixture
def session(assistant, monkeypatch):
    sent, connects = [], []
    device = SimpleNamespace(address='192.0.2.10', port=2222, username='ssh-user', credential_ref='ssh-login', kind='switches')
    channel = SimpleNamespace(sendall=sent.append, close=lambda: None)
    client = SimpleNamespace(set_missing_host_key_policy=lambda policy: None,
                             connect=lambda *a, **kw: connects.append((a, kw)),
                             invoke_shell=lambda **kwargs: channel, close=lambda: None)
    state = SimpleNamespace(device=lambda target, **kwargs: device, target_lock=lambda target: nullcontext())
    assistant.secrets.set('ssh-login', 'SYNTHETIC-SSH-LOGIN')
    outputs = ['switch# ', 'output\nswitch# ']
    monkeypatch.setattr(device_ssh.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(device_ssh, 'shell_read', lambda *args: outputs.pop(0))
    return state, assistant.secrets, device, channel, client, outputs, sent, connects


@pytest.mark.parametrize('kind', ['fmc', 'ftd', 'switches', 'routers', 'endpoints', 'traffic_generators'])
def test_all_enrolled_categories_and_unrestricted_command_text(session, kind):
    state, secrets, device, channel, client, outputs, sent, connects = session
    device.kind = kind
    device.address = 'https://fmc.example.invalid:8443' if kind == 'fmc' else '192.0.2.10'
    command = "printf '%s\\n' hello | sort; echo $(hostname)\nshow version"
    result = device_ssh.execute(state, secrets, 'enrolled', 'Run my requested commands', [command])
    assert result['ok']
    assert sent == [command + '\n']
    assert connects[0][0][0] == ('fmc.example.invalid' if kind == 'fmc' else '192.0.2.10')
    assert connects[0][1]['port'] == 2222
    assert connects[0][1]['password'] == 'SYNTHETIC-SSH-LOGIN'
    assert 'SYNTHETIC' not in json.dumps(result)


def test_shell_preserves_context_and_stops_after_cli_error(session):
    state, secrets, _, _, _, outputs, sent, _ = session
    outputs[:] = ['sw# ', 'sw(config)# ', '% Invalid input\nsw(config)# ']
    result = device_ssh.execute(state, secrets, 'enrolled', 'Configure interface', ['conf t', 'bad command', 'do not send'])
    assert not result['ok']
    assert sent == ['conf t\n', 'bad command\n']
    assert result['commands'][-1]['status'] == 'command_failed'
    assert result['automatic_retries'] == 0


def test_timeout_retains_redacted_partial_evidence_without_replay(session, monkeypatch):
    state, secrets, _, _, _, _, sent, _ = session
    def read(*args):
        if not sent:
            return 'sw# '
        raise AssistantError('ssh_prompt_timeout', 'Timeout', output='partial SYNTHETIC-SSH-LOGIN')
    monkeypatch.setattr(device_ssh, 'shell_read', read)
    result = device_ssh.execute(state, secrets, 'enrolled', 'Configure', ['change', 'later'])
    assert sent == ['change\n']
    assert result['commands'][0]['status'] == 'outcome_unknown'
    assert result['configuration_may_have_changed']
    assert result['error']['output'] == 'partial [REDACTED]'


def test_secret_templates_do_not_expose_resolved_values(session):
    state, secrets, _, _, _, outputs, sent, _ = session
    secrets.set('local-key', 'SYNTHETIC-KEY')
    outputs[:] = ['sw# ', 'command SYNTHETIC-KEY\nsw# ']
    result = device_ssh.execute(state, secrets, 'enrolled', 'Configure using local key',
                                [{'template': 'command {{key}}', 'values': {'key': {'$secret': 'local-key'}}}])
    assert sent == ['command SYNTHETIC-KEY\n']
    assert 'SYNTHETIC-KEY' not in json.dumps(result)


def test_exec_exit_status_and_stderr_are_reported(session, monkeypatch):
    state, secrets, _, _, client, _, _, _ = session
    commands, closes = [], []
    channels = [SimpleNamespace(exec_command=commands.append, close=lambda: closes.append(True)) for _ in range(2)]
    client.get_transport = lambda: SimpleNamespace(open_session=lambda **kwargs: channels.pop(0))
    replies = iter([('first', '', 0), ('', 'failure', 7)])
    monkeypatch.setattr(device_ssh, 'exec_read', lambda *args: next(replies))
    result = device_ssh.execute(state, secrets, 'enrolled', 'Execute shell', ['ls | sort', 'exit 7', 'later'], mode='exec')
    assert not result['ok']
    assert commands == ['ls | sort', 'exit 7']
    assert len(closes) == 2
    assert result['commands'][-1]['stderr'] == 'failure'
    assert result['commands'][-1]['exit_status'] == 7


@pytest.mark.parametrize('prompt', ['switch(config-if)# ', '> ', 'user@host:~$ ', 'router# '])
def test_network_and_os_prompts(prompt):
    channel = Channel([('output\n' + prompt).encode()])
    assert prompt.strip() in device_ssh.shell_read(channel, device_ssh.re.compile(device_ssh.DEFAULT_PROMPT), [], 1)


def test_paging_and_explicit_prompt_response():
    channel = Channel([b'output\n--More--', b'\nDestination filename [startup-config]? ', b'\n[OK]\nsw# '])
    output = device_ssh.shell_read(channel, device_ssh.re.compile(device_ssh.DEFAULT_PROMPT),
                                  [(device_ssh.re.compile(r'Destination filename.*\?\s*$'), '')], 2)
    assert channel.sent == [' ', '\n']
    assert '[OK]' in output


def test_no_automatic_privilege_password():
    channel = Channel([b'Password: '])
    with pytest.raises(AssistantError, match='interactive response'):
        device_ssh.shell_read(channel, device_ssh.re.compile(device_ssh.DEFAULT_PROMPT), [], 1)
    assert not channel.sent


def test_fmc_ssh_account_does_not_reuse_https_account(tmp_path):
    path = tmp_path / 'devices.yaml'
    path.write_text(yaml.safe_dump({'format_version': 3, 'devices': {'fmc': [{
        'device_name': 'fmc', 'hostname': 'fmc.example.invalid', 'https_port': 8443, 'ssh_port': 2222,
        'ssh_username': 'ssh-account', 'ssh_password': 'SYNTHETIC-SSH',
        'https_username': 'https-account', 'https_password': 'SYNTHETIC-HTTPS'}]}}))
    state = State(tmp_path / 'config', tmp_path / 'data', path)
    assert state.device('fmc').username == 'https-account'
    assert state.device('fmc', protocol='ssh').username == 'ssh-account'
    assert state.device('fmc', protocol='ssh').port == 2222


def test_explicit_console_replies_resolve_selected_device_account(session, monkeypatch):
    state, secrets, _, _, _, _, _, _ = session
    observed = []
    def read(channel, prompt, replies, timeout, authenticating=False):
        observed.append([response for _, response in replies])
        return 'sw# '
    monkeypatch.setattr(device_ssh, 'shell_read', read)
    result = device_ssh.execute(state, secrets, 'enrolled', 'Inspect console-connected switch', ['show version'],
                                prompt_responses=[{'pattern': r'login:\s*$', 'response': {'$device': 'ssh_username'}},
                                                  {'pattern': r'Password:\s*$', 'response': {'$device': 'ssh_password'}}])
    assert result['ok']
    assert observed[0] == ['ssh-user', 'SYNTHETIC-SSH-LOGIN']
    assert 'SYNTHETIC' not in json.dumps(result)


def test_answered_prompt_is_not_resubmitted_on_ansi_or_whitespace_chunks():
    channel = Channel([b'Password: ', bytes([27]) + b'[0m', b' ', b'\nAuthenticated\nsw# '])
    output = device_ssh.shell_read(channel, device_ssh.re.compile(device_ssh.DEFAULT_PROMPT),
                                  [(device_ssh.re.compile(r'Password:\s*$'), 'fixture')], 2)
    assert channel.sent == ['fixture\n']
    assert 'Authenticated' in output


def test_console_login_failure_stops_before_another_credential_reply():
    channel = Channel([b'Login incorrect\nUser Access Verification\nswitch login: '])
    with pytest.raises(AssistantError) as error:
        device_ssh.shell_read(channel, device_ssh.re.compile(device_ssh.DEFAULT_PROMPT),
                              [(device_ssh.re.compile(r'login:\s*$'), 'fixture')], 1, True)
    assert error.value.code == 'ssh_console_authentication_failed'
    assert channel.sent == []


def test_console_account_can_differ_from_ssh_transport(session, monkeypatch):
    state, secrets, device, _, _, _, _, connects = session
    original = state.device
    state.device = lambda target, **kwargs: (SimpleNamespace(username='device-admin')
                                             if kwargs.get('protocol') == 'https' else original(target, **kwargs))
    calls = []
    original_get = secrets.get
    def get(reference, protocol=None):
        calls.append(protocol)
        if protocol == 'https':
            secrets.redactor.register('SYNTHETIC-CONSOLE-LOGIN')
            return 'SYNTHETIC-CONSOLE-LOGIN'
        return original_get(reference, protocol=protocol)
    monkeypatch.setattr(secrets, 'get', get)
    replies = []
    def read(channel, prompt, responses, timeout, authenticating=False):
        replies.extend(response for _, response in responses)
        return 'sw# '
    monkeypatch.setattr(device_ssh, 'shell_read', read)
    result = device_ssh.execute(state, secrets, 'enrolled', 'Read console switch', ['show version'],
                                prompt_responses=[{'pattern': 'login:', 'response': {'$device': 'https_username'}},
                                                  {'pattern': 'Password:', 'response': {'$device': 'https_password'}}])
    assert result['ok']
    assert connects[0][1]['username'] == 'ssh-user'
    assert connects[0][1]['password'] == 'SYNTHETIC-SSH-LOGIN'
    assert replies[:2] == ['device-admin', 'SYNTHETIC-CONSOLE-LOGIN']
    assert 'https' in calls and 'ssh' in calls
    assert 'SYNTHETIC' not in json.dumps(result)
