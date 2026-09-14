#!/usr/bin/env python3
"""Validate public traffic listener wire examples; requires jsonschema."""
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator


class TrafficListenerSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        document = json.loads((Path(__file__).resolve().parents[1] / 'docs/openapi.json').read_text())
        cls.schema = document['components']['schemas']['TrafficListener']
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def test_valid_namespaces(self):
        for kind, identifier in [('default', 'default'), ('public', 'edge'),
                                 ('workload', 'private:edge'), ('unknown', None)]:
            with self.subTest(kind=kind):
                self.validator.validate({'kind': kind, 'id': identifier})

    def test_impossible_and_malformed_provenance(self):
        for kind, identifier in [('default', 'edge'), ('public', None),
                                 ('public', 'default'), ('public', 'a' * 65),
                                 ('workload', 'a' * 129), ('unknown', 'edge'),
                                 ('public', 'edge\n'), ('workload', 'edge\n'),
                                 ('public', 'edge/other'), ('invented', 'edge')]:
            with self.subTest(kind=kind, identifier=identifier):
                self.assertFalse(self.validator.is_valid({'kind': kind, 'id': identifier}))


if __name__ == '__main__':
    unittest.main()
