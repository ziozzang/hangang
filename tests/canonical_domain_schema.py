#!/usr/bin/env python3
"""Executable OpenAPI checks for canonical-domain route policy grammar."""
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator


DOCUMENT = json.loads(
    (Path(__file__).resolve().parents[1] / 'docs/openapi.json').read_bytes()
)


def validator(name):
    return Draft202012Validator({
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'components': DOCUMENT['components'],
        '$ref': '#/components/schemas/' + name,
    })


class CanonicalDomainSchema(unittest.TestCase):
    def test_defaults_form_a_valid_policy(self):
        check = validator('CanonicalDomainRedirect')
        self.assertTrue(check.is_valid({'host': 'example.test'}))
        self.assertTrue(check.is_valid({
            'enabled': True,
            'host': 'example.test',
            'scheme': 'https',
            'status': 302,
            'path_prefixes': ['/'],
            'exclude_path_prefixes': [],
            'methods': ['GET', 'HEAD'],
        }))

    def test_target_is_an_exact_dns_name(self):
        check = validator('CanonicalDomainRedirect')
        for host in ['example.test\n', '*.example.test', '192.0.2.1']:
            with self.subTest(host=host):
                self.assertFalse(check.is_valid({'host': host}))

    def test_prefix_rejects_unsafe_or_ambiguous_paths(self):
        check = validator('CanonicalDomainRedirect')
        for prefix in [
            '/search?q=x', '/fragment#x', '/windows\\path', '/a/../b',
            '/./a', '/line\nfeed', '/nul\x00byte',
        ]:
            with self.subTest(prefix=prefix):
                policy = {'host': 'example.test', 'path_prefixes': [prefix]}
                self.assertFalse(check.is_valid(policy))

    def test_http_route_references_nullable_policy(self):
        check = validator('HttpRoute')
        route = {'id': 'site', 'backends': ['http://127.0.0.1:8080']}
        self.assertTrue(check.is_valid(route))
        self.assertTrue(check.is_valid({**route, 'canonical_domain': None}))
        self.assertTrue(check.is_valid({
            **route, 'host': 'example.test',
            'canonical_domain': {'host': 'example.test'},
        }))
        self.assertFalse(check.is_valid({
            **route, 'canonical_domain': {'host': 'example.test\n'},
        }))


if __name__ == '__main__':
    unittest.main()
