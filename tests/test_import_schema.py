import importlib.util
from pathlib import Path

from secure_firewall_assistant.catalog import Catalog


def test_example_password_placeholder_does_not_corrupt_boolean_schema(monkeypatch):
    scripts = Path(__file__).resolve().parents[1] / 'scripts'
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location('import_schema', scripts / 'import_schema.py')
    importer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(importer)
    document = {
        'paths': {'/devices': {'get': {
            'operationId': 'getAllDevice',
            'parameters': [{'name': 'expanded', 'in': 'query', 'schema': {'type': 'boolean'}}],
        }}},
        'components': {'schemas': {}},
        'example': {'password': 'boolean', 'secret': 'sample-sensitive-value'},
        'description': 'sample-sensitive-value',
    }
    cleaned = importer.sanitize(document, importer.example_credentials(document))
    assert cleaned['description'] == '[EXAMPLE CREDENTIAL REMOVED]'
    assert 'example' not in cleaned
    catalog = Catalog(cleaned)
    assert catalog.prepare('getAllDevice', {}, {'expanded': True}, {}, None, '')['query'] == {'expanded': True}
    import pytest

    from secure_firewall_assistant.errors import AssistantError
    with pytest.raises(AssistantError) as error:
        catalog.prepare('getAllDevice', {}, {'expanded': 'true'}, {}, None, '')
    assert error.value.code == 'request_validation_failed'
