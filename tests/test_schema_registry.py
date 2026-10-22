import asyncio
import base64
import gzip
import json
import os

import httpx
import pytest
from mcp import Client

from secure_firewall_assistant.catalog import DATA
from secure_firewall_assistant.errors import AssistantError
from secure_firewall_assistant.schema_registry import (
    RemoteCatalogProvider,
    SchemaRegistry,
    decode_package,
    publish,
)
from secure_firewall_assistant.schema_server import build_schema_server


def registry(tmp_path):
    publish(tmp_path, DATA / 'fmc.openapi.json.gz', '10.5.0.0', 'r1')
    return SchemaRegistry(tmp_path)


def test_exact_numeric_latest_and_revision_immutability(tmp_path):
    original_mode = tmp_path.stat().st_mode & 0o777
    value = registry(tmp_path)
    assert value.resolve('10.5.0 (build 1)')['selection'] == 'exact'
    assert value.resolve('10.1.0 (build 160)')['selection'] == 'latest_fallback'
    publish(tmp_path, DATA / 'fmc.openapi.json.gz', '10.9.0.0', 'r1')
    publish(tmp_path, DATA / 'fmc.openapi.json.gz', '10.10.0.0', 'r1')
    assert value.resolve('11.0.0')['schema_version'] == '10.10.0.0'
    changed = tmp_path / 'changed.json'
    document = decode_package(value.package())
    document['info']['description'] = 'Reviewed correction'
    changed.write_text(json.dumps(document))
    with pytest.raises(AssistantError, match='new revision'):
        publish(tmp_path, changed, '10.5.0.0', 'r1')
    publish(tmp_path, changed, '10.5.0.0', 'r2')
    assert value.resolve('10.5')['revision'] == 'r2'
    assert len(value.versions()) == 3
    assert tmp_path.stat().st_mode & 0o777 == original_mode
    if os.name != 'nt':
        assert (tmp_path / 'index.json').stat().st_mode & 0o777 == 0o644


def test_remote_refresh_cache_integrity_and_no_device_payloads(tmp_path):
    remote = registry(tmp_path / 'registry')
    calls = []
    offline = False
    def handle(request):
        if offline:
            raise httpx.ConnectError('fixture outage')
        body = json.loads(request.content)
        calls.append(body)
        result = {} if body['method'] == 'initialize' else {'structuredContent': remote.package(body['params']['arguments']['fmc_version'])}
        return httpx.Response(200, json={'jsonrpc':'2.0','id':body['id'],'result':result})
    provider = RemoteCatalogProvider(tmp_path / 'cache', transport=httpx.MockTransport(handle), refresh_seconds=0)
    first = provider.get('10.1.0 (build 160)')
    assert first.provenance['selection'] == 'latest_fallback'
    publish(remote.directory, DATA / 'fmc.openapi.json.gz', '10.5.0.0', 'r2')
    second = provider.get('10.1.0 (build 160)')
    assert second.provenance['revision'] == 'r2'
    assert first.provenance['revision'] == 'r1'  # In-flight catalog stays pinned.
    assert all(set(c['params']['arguments']) == {'fmc_version'} for c in calls if c['method'] == 'tools/call')
    offline = True
    assert provider.get('10.1.0 (build 160)').provenance['source'] == 'local_cache_service_unavailable'
    with pytest.raises(AssistantError, match='no cached schema'):
        provider.get('9.9.0')
    path = tmp_path / 'cache/10.1.0.0.json'
    cached = json.loads(path.read_text())
    cached['sha256'] = '0'*64
    path.write_text(json.dumps(cached))
    with pytest.raises(AssistantError, match='checksum'):
        provider.get('10.1.0 (build 160)')
    provider.close()


def test_corrupt_online_package_does_not_silently_use_cache(tmp_path):
    remote = registry(tmp_path / 'registry')
    package = remote.package('10.5')
    package['sha256'] = '0'*64
    def handle(request):
        body = json.loads(request.content)
        return httpx.Response(200, json={'id':body['id'],'result':{} if body['method']=='initialize' else {'structuredContent':package}})
    provider = RemoteCatalogProvider(tmp_path / 'cache', transport=httpx.MockTransport(handle))
    with pytest.raises(AssistantError, match='checksum'):
        provider.get('10.5')
    provider.close()


def test_remote_mcp_is_read_only_and_exposes_real_schema(tmp_path):
    value = registry(tmp_path)
    async def run():
        async with Client(build_schema_server(tmp_path)) as client:
            tools = (await client.list_tools()).tools
            assert len(tools) == 6
            assert all(t.annotations.read_only_hint for t in tools)
            result = await client.call_tool('resolve_schema', {'fmc_version':'10.1.0'})
            data = result.structured_content or json.loads(result.content[0].text)
            assert data['schema_version'] == '10.5.0.0'
            assert data['selection'] == 'latest_fallback'
            result = await client.call_tool('describe_operation', {'operation_id':'createVpnEndpoint','fmc_version':'10.5'})
            data = result.structured_content or json.loads(result.content[0].text)
            assert data['execution_options']['bulk_create_supported'] is True
            assert data['schema_selection']['sha256'] == value.resolve()['sha256']
    asyncio.run(run())


def test_schema_limits_and_invalid_index(tmp_path):
    value = registry(tmp_path)
    package = value.package()
    package['gzip_base64'] = base64.b64encode(gzip.compress(b'{}')).decode()
    with pytest.raises(AssistantError):
        decode_package(package)
    (tmp_path / 'index.json').write_text(json.dumps({'schemas':[{'version':'10.5','revision':'r1','sha256':'../outside'}]}))
    with pytest.raises(AssistantError):
        value.package()
