#!/usr/bin/env python3
"""UDP API contract checks; requires jsonschema (like other schema fixtures)."""
import copy
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = json.loads((ROOT / 'docs/openapi.json').read_text())


def validator(name):
    schema = {'$ref': '#/components/schemas/' + name, 'components': DOCUMENT['components']}
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


class UdpSchema(unittest.TestCase):
    def test_default_udp_and_quic_minimum_are_distinct(self):
        route = {'id': 'relay', 'listen': '127.0.0.1:8443', 'backends': ['127.0.0.1:9443'], 'max_datagram_bytes': 512}
        check = validator('UdpRoute')
        check.validate(route)
        route['protocol'] = 'quic'
        self.assertFalse(check.is_valid(route))
        route['max_datagram_bytes'] = 1200
        check.validate(route)
        route['unexpected'] = True
        self.assertFalse(check.is_valid(route))

    def test_config_udp_is_optional_and_example_is_valid(self):
        check = validator('Config')
        check.validate({'revision': 0, 'http': [], 'tcp': []})
        check.validate(json.loads((ROOT / 'examples/udp/config.json').read_text()))

    def test_counters_belong_to_each_active_listener(self):
        route = {'id': 'relay', 'enabled': True, 'listen': '127.0.0.1:8443',
                 'protocol': 'udp', 'sessions': 0, 'max_sessions': 1024,
                 'backend_count': 1, 'datagrams_received': 3,
                 'datagrams_forwarded': 2, 'responses_forwarded': 1,
                 'dropped_datagrams': 1, 'sessions_created': 1}
        status = {'routes': [route]}
        check = validator('UdpStatus')
        check.validate(status)
        check.validate({'routes': []})
        invalid = copy.deepcopy(status)
        invalid['datagrams_received'] = invalid['routes'][0].pop('datagrams_received')
        self.assertFalse(check.is_valid(invalid))


if __name__ == '__main__':
    unittest.main()
