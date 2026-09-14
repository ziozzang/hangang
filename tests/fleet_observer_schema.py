"""Executable OpenAPI contract checks for the separate observation authority."""
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

DOCUMENT = json.loads((Path(__file__).resolve().parents[1] / 'docs/openapi.json').read_bytes())


def validator(name):
    return Draft202012Validator({
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'components': DOCUMENT['components'],
        '$ref': '#/components/schemas/' + name,
    })


class FleetObserverSchema(unittest.TestCase):
    def test_observer_document_is_redacted_and_canonical(self):
        check = validator('FleetObservation')
        value = {
            'schema_version': 1, 'node_id': 'edge-a', 'observer_generation': '1',
            'instance_id': '0123456789abcdef', 'configuration_source': 'file',
            'revision': '0', 'config_digest': '0123456789abcdef', 'ready': True,
            'store_epoch': None,
        }
        self.assertTrue(check.is_valid(value))
        for field, invalid in [
            ('node_id', 'edge-a\n'), ('node_id', 'a' * 65), ('node_id', '한강'),
            ('observer_generation', '01'), ('observer_generation', '1\n'),
            ('revision', '00'), ('revision', 1), ('ready', 'true'),
            ('instance_id', '0123456789abcdef\n'), ('token', 'must-never-appear'),
        ]:
            with self.subTest(field=field, invalid=invalid):
                self.assertFalse(check.is_valid({**value, field: invalid}))

    def test_status_disabled_and_configured_states_are_distinct(self):
        check = validator('FleetObserverStatus')
        disabled = {'configured': False, 'available': False, 'node_id': None, 'generation': None}
        self.assertTrue(check.is_valid(disabled))
        enabled = {'configured': True, 'available': True, 'node_id': 'edge-a', 'generation': '1'}
        self.assertTrue(check.is_valid(enabled))
        self.assertTrue(check.is_valid({**enabled, 'available': False}))
        for invalid in [
            {**disabled, 'available': True}, {**disabled, 'node_id': 'edge-a'},
            {**enabled, 'node_id': None}, {**enabled, 'generation': None},
            {**enabled, 'generation': '01'}, {**enabled, 'generation': '2\n'},
            {**enabled, 'token_file': '/private/observer-token'},
        ]:
            self.assertFalse(check.is_valid(invalid), invalid)

    def test_machine_security_is_explicit_and_separate(self):
        operation = DOCUMENT['paths']['/v1/fleet/observation']['get']
        machine_security = operation['security']
        self.assertNotEqual(machine_security, DOCUMENT.get('security'))
        self.assertEqual(len(machine_security), 1)
        name = next(iter(machine_security[0]))
        scheme = DOCUMENT['components']['securitySchemes'][name]
        self.assertEqual(scheme['type'], 'http')
        self.assertEqual(scheme['scheme'], 'bearer')
        self.assertIn('503', operation['responses'])


if __name__ == '__main__':
    unittest.main()
