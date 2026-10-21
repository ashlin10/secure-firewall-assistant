import asyncio
import json
import time

import httpx
import pytest
from mcp import Client

from secure_firewall_assistant.enrollment_ui import MIME, SANDBOX_ORIGIN, EnrollmentUI
from secure_firewall_assistant.server import build_server
from secure_firewall_assistant.state import Device, State


class Store:
    def __init__(self):
        self.values = {}

    def set(self, reference, value, device=None):
        self.values[reference] = value


@pytest.fixture
def form(tmp_path):
    state = State(tmp_path / 'config', tmp_path / 'data', tmp_path / 'devices.yaml')
    store = Store()
    ui = EnrollmentUI(state, store)
    result = ui.start('fmc', 'fixture', 'https://fmc.example.invalid:12202', 'tester')
    metadata = result.model_dump(by_alias=True)['_meta']['enrollment']
    yield ui, metadata, state, store
    ui.close()


def headers(meta):
    return {'Origin': SANDBOX_ORIGIN, 'X-SFA-Enrollment': meta['authorization']}


def fields(**updates):
    return {'password': 'synthetic-inline-value', 'repeat': 'synthetic-inline-value',
            **updates}


def test_inline_completion_is_private_and_single_use(form, capsys):
    ui, meta, state, store = form
    response = httpx.post(meta['endpoint'], json=fields(), headers=headers(meta))
    assert response.status_code == 200
    assert response.headers['Access-Control-Allow-Origin'] == SANDBOX_ORIGIN
    assert response.headers['Cache-Control'] == 'no-store'
    assert store.values == {'fixture-auth': 'synthetic-inline-value'}
    assert 'synthetic-inline-value' not in response.text
    assert 'synthetic-inline-value' not in state.inventory_path.read_text()
    assert state.device('fixture').domain is None
    assert ui.status(meta['endpoint'].rsplit('/', 1)[1])['status'] == 'enrolled'
    assert httpx.post(meta['endpoint'], json=fields(), headers=headers(meta)).status_code == 403
    assert 'synthetic-inline-value' not in str(capsys.readouterr())


@pytest.mark.parametrize('change', [
    {'Origin': 'https://evil.example'}, {'Origin': 'null'}, {'Host': 'evil.example'},
    {'X-SFA-Enrollment': 'wrong'}, {'Origin': 'http://localhost'},
])
def test_forged_origin_host_and_authorization_fail_closed(form, change):
    ui, meta, state, store = form
    response = httpx.post(meta['endpoint'], json=fields(), headers={**headers(meta), **change})
    assert response.status_code == 403
    assert state.aliases() == [] and store.values == {}
    if change.get('Origin') and change['Origin'] != SANDBOX_ORIGIN:
        assert 'Access-Control-Allow-Origin' not in response.headers


def test_preflight_is_exact_and_no_browser_page_exists(form):
    ui, meta, state, store = form
    response = httpx.options(meta['endpoint'], headers={'Origin': SANDBOX_ORIGIN,
        'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type,x-sfa-enrollment'})
    assert response.status_code == 200
    assert response.headers['Access-Control-Allow-Private-Network'] == 'true'
    probe_url = meta['endpoint'] + '/probe'
    probe_preflight = httpx.options(probe_url, headers={'Origin': SANDBOX_ORIGIN,
        'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'x-sfa-enrollment'})
    assert probe_preflight.status_code == 200
    assert httpx.get(probe_url, headers=headers(meta)).json() == {'ok': True}
    assert httpx.get(probe_url, headers={**headers(meta), 'X-SFA-Enrollment': 'wrong'}).status_code == 403
    for change in [{'Access-Control-Request-Method': 'DELETE'}, {'Access-Control-Request-Headers': 'x-arbitrary'}]:
        assert httpx.options(meta['endpoint'], headers={'Origin': SANDBOX_ORIGIN,
            'Access-Control-Request-Method': 'POST', **change}).status_code == 403
    assert httpx.get(meta['endpoint']).status_code == 403


def test_invalid_fields_expiry_and_existing_alias_leave_credentials_untouched(form):
    ui, meta, state, store = form
    for values in [fields(repeat='different'), fields(ca='/nonexistent/ca.pem'), fields(password=[]), {'password': 'x'}]:
        response = httpx.post(meta['endpoint'], json=values, headers=headers(meta))
        assert response.status_code == 400
        assert 'synthetic-inline-value' not in response.text
    identifier = meta['endpoint'].rsplit('/', 1)[1]
    state.save_device(Device('fixture', 'fmc', 'https://different.example.invalid',
                             'other-user', 'fixture-auth'))
    assert httpx.post(meta['endpoint'], json=fields(), headers=headers(meta)).status_code == 409
    ui.sessions[identifier]['expires'] = time.time() - 1
    assert httpx.post(meta['endpoint'], json=fields(), headers=headers(meta)).status_code == 403
    assert ui.status(identifier)['status'] == 'expired'
    assert store.values == {}


def test_mcp_card_metadata_and_resource_roundtrip(assistant):
    async def run():
        async with Client(build_server(assistant)) as client:
            tools = (await client.list_tools()).tools
            descriptor = next(t for t in tools if t.name == 'start_enrollment').model_dump(by_alias=True)
            assert 'password' not in json.dumps(descriptor['inputSchema']).lower()
            uri = descriptor['_meta']['ui']['resourceUri']
            assert descriptor['_meta']['openai/ui']['entrypoints'] == [{'type':'global'}, {'type':'thread'}]
            resource = (await client.read_resource(uri)).contents[0].model_dump(by_alias=True)
            assert resource['mimeType'] == MIME
            assert resource['_meta']['ui']['csp']['resourceDomains'] == []
            assert len(resource['_meta']['ui']['csp']['connectDomains']) == 1
            html = resource['text']
            assert 'type="password"' in html and "'ui/initialize'" in html
            assert 'Check local connection' in html and "'/probe'" in html
            assert "'ui/notifications/tool-result'" in html
            assert 'setWidgetState' not in html and 'console.log' not in html and 'window.open(' not in html
            result = (await client.call_tool('start_enrollment', {
                'kind':'fmc','alias':'new-fixture','address':'https://example.invalid','username':'tester'})).model_dump(by_alias=True)
            assert 'endpoint' not in json.dumps(result['content'])
            assert 'authorization' not in json.dumps(result['structuredContent'])
            public = result['structuredContent'] or json.loads(result['content'][0]['text'])
            assert public['status'] == 'enter_device_details'
            assert public['prefill']['alias'] == 'new-fixture'
            result = (await client.call_tool('start_enrollment', {
                'kind':'fmc','alias':'new-fixture','address':'https://example.invalid','username':'tester',
                'confirm_details':True})).model_dump(by_alias=True)
            assert result['_meta']['enrollment']['endpoint'].startswith('http://127.0.0.1:')
            assert result['structuredContent']['status'] == 'waiting_for_private_form'
            assert 'enrollment_url' not in json.dumps(result)
            status = await client.call_tool('enrollment_status', {'enrollment_id':result['structuredContent']['enrollment_id']})
            assert 'waiting' in json.dumps(status.model_dump())
    asyncio.run(run())


def test_card_keeps_password_out_of_host_bridge():
    import shutil
    import subprocess
    from pathlib import Path
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is needed for the component JavaScript boundary test')
    root = Path(__file__).resolve().parents[1]
    subprocess.run([node, str(root / 'tests/card_flow.mjs'),
                    str(root / 'src/secure_firewall_assistant/enrollment_card.html')], check=True)


def test_status_remains_responsive_during_native_store_prompt(form):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    ui, meta, state, store = form
    entered, release = threading.Event(), threading.Event()
    original = store.set

    def prompted_set(reference, value, **kwargs):
        entered.set()
        assert release.wait(5), 'test did not release synthetic file-save wait'
        original(reference, value, **kwargs)

    store.set = prompted_set
    identifier = meta['endpoint'].rsplit('/', 1)[1]
    with ThreadPoolExecutor(max_workers=2) as pool:
        saving = pool.submit(httpx.post, meta['endpoint'], json=fields(), headers=headers(meta))
        try:
            assert entered.wait(3)
            assert pool.submit(ui.status, identifier).result(timeout=1)['status'] == 'saving'
            assert httpx.post(meta['endpoint'], json=fields(), headers=headers(meta)).status_code == 403
        finally:
            release.set()
        assert saving.result(timeout=3).status_code == 200
    assert ui.status(identifier)['status'] == 'enrolled'


def test_native_store_failure_can_be_retried_without_false_success(form):
    ui, meta, state, store = form
    original = store.set

    def fail(*args):
        raise RuntimeError('synthetic-private-error')

    store.set = fail
    response = httpx.post(meta['endpoint'], json=fields(), headers=headers(meta))
    assert response.status_code == 500
    assert 'synthetic-private-error' not in response.text
    assert ui.status(meta['endpoint'].rsplit('/', 1)[1])['status'] == 'waiting'
    assert state.aliases() == []
    store.set = original
    assert httpx.post(meta['endpoint'], json=fields(), headers=headers(meta)).status_code == 200


def test_enrollment_preserves_explicit_domain_without_card_overrides(form):
    ui, meta, state, store = form
    result = ui.start('fmc', 'domain-fixture', 'https://fmc.example.invalid', 'tester', domain='Lab')
    meta = result.model_dump(by_alias=True)['_meta']['enrollment']
    assert httpx.post(meta['endpoint'], json=fields(domain='Other'), headers=headers(meta)).status_code == 400
    assert httpx.post(meta['endpoint'], json=fields(), headers=headers(meta)).status_code == 200
    assert state.device('domain-fixture').domain == 'Lab'
