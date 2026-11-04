import importlib.util
from pathlib import Path

from secure_firewall_assistant.catalog import Catalog

SPEC = importlib.util.spec_from_file_location('converter', Path(__file__).resolve().parents[1] / 'scripts/convert_swagger.py')
converter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(converter)


def test_swagger_conversion_preserves_request_validation_and_refs():
    operation = {'operationId': 'createNetwork', 'parameters': [
        {'$ref': '#/parameters/limit'}, {'in': 'body', 'name': 'body', 'required': True,
            'schema': {'$ref': '#/definitions/Network'}}],
        'responses': {'201': {'description': 'created', 'schema': {'$ref': '#/definitions/Network'}}}}
    document = {'swagger': '2.0', 'info': {'title': 'FMC', 'version': '1'},
        'consumes': ['application/json'], 'produces': ['application/json'],
        'parameters': {'limit': {'in': 'query', 'name': 'limit', 'type': 'integer'}},
        'definitions': {'Network': {'type': 'object', 'required': ['name'],
            'properties': {'name': {'type': 'string'}}}},
        'paths': {'/object/networks': {'post': operation}}}
    out = converter.convert_swagger(document)
    catalog = Catalog(out)
    op = catalog.describe('createNetwork')
    assert op['parameters'][0]['schema'] == {'type': 'integer'}
    body = op['request_body']['content']['application/json']['schema']
    assert catalog.resolve(body)['required'] == ['name']
    assert op['request_body']['required']
    assert out['paths']['/object/networks']['post']['responses']['201']['content']['application/json']['schema'] == body
    assert document['swagger'] == '2.0' and 'components' not in document


def test_swagger_file_upload_becomes_binary_multipart_body():
    operation = {'operationId': 'upload', 'consumes': ['multipart/form-data'],
        'parameters': [{'in': 'formData', 'name': 'file', 'type': 'file', 'required': True}],
        'responses': {'200': {'description': 'ok'}}}
    document = {'swagger': '2.0', 'info': {'title': 'FMC', 'version': '1'},
        'paths': {'/upload': {'post': operation}}}
    schema = converter.convert_swagger(document)['paths']['/upload']['post']['requestBody']['content']['multipart/form-data']['schema']
    assert schema['properties']['file'] == {'type': 'string', 'format': 'binary'}
    assert schema['required'] == ['file']
