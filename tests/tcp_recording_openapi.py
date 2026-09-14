"""Focused wire-schema examples for selective raw TCP completion recording."""
import json
from pathlib import Path
import re
import unittest


SCHEMAS = json.loads((Path(__file__).resolve().parents[1] / 'docs/openapi.json').read_bytes())['components']['schemas']


class TcpRecordingOpenApi(unittest.TestCase):
    def test_tcp_decimal_rejects_newline_sign_leading_zero_and_overlength(self):
        schema = SCHEMAS['TcpDecimal']
        pattern = re.compile(schema['pattern'])
        for value in ('0', '25', '18446744073709551615'):
            self.assertLessEqual(len(value), schema['maxLength'])
            self.assertIsNotNone(pattern.match(value), value)
        for value in ('', '01', '-1', '+1', '1\n', '1\r', '1x', '1'*21):
            self.assertTrue(len(value) > schema['maxLength'] or pattern.match(value) is None,
                            value)

    def test_recent_fields_and_policy_wire_names(self):
        record = SCHEMAS['TcpRecentRecord']
        batch = SCHEMAS['TcpRecentBatch']
        policy = SCHEMAS['TcpRecentRecordingPolicy']
        match = SCHEMAS['TcpRecentRecordingMatch']
        self.assertIn('policy_revision', record['required'])
        self.assertEqual(record['properties']['policy_revision']['anyOf'][1], {'type':'null'})
        self.assertIn('filtered_total', batch['required'])
        self.assertEqual(batch['properties']['filtered_total']['$ref'], '#/components/schemas/TcpDecimal')
        self.assertEqual(policy['properties']['default_action']['enum'], ['record','drop'])
        self.assertEqual(policy['properties']['rules']['maxItems'], 64)
        self.assertEqual(set(match['properties']),
                         {'listen_addresses','peer_cidrs','route_ids','route_matched','outcomes'})
        self.assertEqual(match['properties']['outcomes']['items']['$ref'], '#/components/schemas/TcpOutcome')
        self.assertEqual(SCHEMAS['Settings']['properties']['tcp_recent_recording']['anyOf'][0]['$ref'],
                         '#/components/schemas/TcpRecentRecordingPolicy')

    def test_rule_ids_are_absolute_ended_and_unmatched_routes_have_no_ids(self):
        rule = SCHEMAS['TcpRecentRecordingRule']
        criteria = SCHEMAS['TcpRecentRecordingMatch']
        for schema in (rule['properties']['id'], criteria['properties']['route_ids']['items']):
            pattern = re.compile(schema['pattern'])
            self.assertIsNotNone(pattern.match('raw.route-1'))
            for bad in ('raw\n', 'raw\r', 'raw/', 'raw '):
                self.assertIsNone(pattern.match(bad), bad)
        condition = criteria['allOf'][0]
        self.assertEqual(condition['if']['properties']['route_matched']['const'], False)
        self.assertEqual(condition['if']['required'], ['route_matched'])
        self.assertEqual(condition['then']['properties']['route_ids']['maxItems'], 0)

    def test_actual_draft202012_examples_when_validator_is_installed(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest('jsonschema is not installed in this environment')
        schema = {'$schema':'https://json-schema.org/draft/2020-12/schema',
                  'components':{'schemas':SCHEMAS},
                  '$ref':'#/components/schemas/TcpRecentRecordingRule'}
        validator = Draft202012Validator(schema)
        good = {'id':'raw','action':'record',
                'match':{'route_matched':False,'route_ids':[]}}
        self.assertTrue(validator.is_valid(good))
        for bad in (
            {'id':'raw\n','action':'record','match':{}},
            {'id':'raw','action':'record','match':{'route_ids':['old\n']}},
            {'id':'raw','action':'record',
             'match':{'route_matched':False,'route_ids':['old']}},
        ):
            self.assertFalse(validator.is_valid(bad), bad)


if __name__ == '__main__':
    unittest.main()
