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


if __name__ == '__main__':
    unittest.main()
