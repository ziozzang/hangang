"""Actual JSON Schema checks for unknown coverage and historical fleet evidence."""
import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

DOCUMENT = json.loads((Path(__file__).resolve().parents[1] / 'docs/openapi.json').read_bytes())


def validator(name):
    return Draft202012Validator({
        'components': DOCUMENT['components'], '$ref': '#/components/schemas/' + name,
    })


def observation():
    return {'schema_version': 1, 'node_id': 'edge-a', 'observer_generation': '1',
            'instance_id': '0123456789abcdef', 'configuration_source': 'file', 'revision': '0',
            'config_digest': 'abcdef0123456789', 'ready': False, 'store_epoch': None}


def node():
    return {'node_id': 'edge-a', 'endpoint': 'https://edge-a.example:9443',
            'group_id': None, 'role': None,
            'condition': 'fresh', 'last_error': None, 'age_seconds': 0,
            'observation': observation()}


class FleetCollectorSchema(unittest.TestCase):
    def test_unavailable_inventory_is_not_an_empty_inventory(self):
        check = validator('FleetObservations')
        disabled = {'configured': False, 'available': False, 'generation': None,
                    'observer_instance_id': '0123456789abcdef', 'expected_nodes': 0,
                    'fresh_nodes': 0, 'stale_after_seconds': 60, 'nodes': []}
        unavailable = {**disabled, 'configured': True, 'generation': '2',
                       'expected_nodes': None, 'fresh_nodes': None}
        empty = {**disabled, 'configured': True, 'available': True, 'generation': '1'}
        for good in (disabled, unavailable, empty):
            self.assertTrue(check.is_valid(good), list(check.iter_errors(good)))
        for bad in ({**unavailable, 'expected_nodes': 0, 'fresh_nodes': 0},
                    {**empty, 'expected_nodes': None}, {**empty, 'generation': None},
                    {**disabled, 'available': True}, {**empty, 'observer_instance_id': 'x'},
                    {key: value for key, value in empty.items() if key != 'observer_instance_id'}):
            self.assertFalse(check.is_valid(bad), bad)

    def test_freshness_is_not_reported_readiness(self):
        check = validator('FleetCollectedNode')
        good = node()
        self.assertFalse(good['observation']['ready'])
        self.assertTrue(check.is_valid(good))
        unknown = {**good, 'condition': 'unknown', 'observation': None, 'age_seconds': None}
        historical = {**good, 'condition': 'unavailable', 'age_seconds': 1000, 'last_error': 'transport'}
        stale = {**good, 'condition': 'stale', 'age_seconds': 60}
        for value in (unknown, historical, stale):
            self.assertTrue(check.is_valid(value), list(check.iter_errors(value)))
        for bad in ({**good, 'age_seconds': 60}, {**good, 'last_error': 'transport'},
                    {**good, 'observation': None}, {**stale, 'age_seconds': 59},
                    {**unknown, 'observation': observation()},
                    {**historical, 'last_error': None}, {**historical, 'age_seconds': None},
                    {**historical, 'condition': 'identity_mismatch'},
                    {**good, 'token_file': '/private/token'}):
            self.assertFalse(check.is_valid(bad), bad)

    def test_collected_wire_is_stricter_than_uninterpreted_peer_metadata(self):
        check = validator('FleetCollectedNode')
        for bad_epoch in ('', 'has space', 'line\n', '\x7f', '한강'):
            value = node()
            value['observation']['store_epoch'] = bad_epoch
            self.assertFalse(check.is_valid(value), bad_epoch)
        value = node()
        value['observation']['store_epoch'] = 'epoch-1'
        self.assertTrue(check.is_valid(value))
        del value['observation']['store_epoch']
        self.assertFalse(check.is_valid(value))
        value = copy.deepcopy(node())
        value['observation']['unexpected'] = 'not allowed'
        self.assertFalse(check.is_valid(value))

    def test_optional_inventory_labels_are_always_nullable_bounded_wire_fields(self):
        check = validator('FleetCollectedNode')
        old_inventory = node()
        self.assertTrue(check.is_valid(old_inventory))
        labelled = {**old_inventory, 'group_id': 'edge-a', 'role': 'gateway'}
        self.assertTrue(check.is_valid(labelled))
        for field in ('group_id', 'role'):
            missing = {key: value for key, value in old_inventory.items() if key != field}
            self.assertFalse(check.is_valid(missing), field)
            for bad in ('', 'a' * 65, 'has space', 'line\n', 'bad/slash', '한강', 7, []):
                value = {**labelled, field: bad}
                self.assertFalse(check.is_valid(value), (field, bad))
        self.assertTrue(check.is_valid({**old_inventory, 'group_id': 'a' * 64,
                                        'role': 'R._-9'}))


if __name__ == '__main__':
    unittest.main()
