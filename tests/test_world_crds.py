"""Static checks for the world.hangang.dev CRDs and examples (ADR 0022 API rules).

Every string carries maxLength (or an enum/format bound), every list maxItems,
every map maxProperties; no x-kubernetes-preserve-unknown-fields; a status
subresource exists. Example objects are checked against the structural schema
(types, required fields, enums, patterns and bounds; CEL rules are mirrored by
the controller's own validation and its unit tests).
"""
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CRD = ROOT / 'deploy/kubernetes/crds/protectionpolicies.world.hangang.dev.yaml'
EXAMPLE = ROOT / 'examples/kubernetes/protection-policy.yaml'


def walk(node, path='$'):
    yield path, node
    for key, child in (node.get('properties') or {}).items():
        yield from walk(child, f'{path}.{key}')
    if isinstance(node.get('items'), dict):
        yield from walk(node['items'], f'{path}[]')
    if isinstance(node.get('additionalProperties'), dict):
        yield from walk(node['additionalProperties'], f'{path}{{}}')


def check(schema, value, path='$'):
    kind = schema.get('type')
    if kind == 'object':
        assert isinstance(value, dict), path
        for name in schema.get('required', []):
            assert name in value, f'{path}.{name} is required'
        properties = schema.get('properties')
        if properties is not None and path != '$.metadata':
            for name, child in value.items():
                assert name in properties, f'{path}.{name} is not in the schema'
                check(properties[name], child, f'{path}.{name}')
    elif kind == 'array':
        assert isinstance(value, list), path
        assert schema.get('minItems', 0) <= len(value) <= schema['maxItems'], path
        for index, item in enumerate(value):
            check(schema['items'], item, f'{path}[{index}]')
        keys = schema.get('x-kubernetes-list-map-keys')
        if keys:
            seen = [tuple(item[k] for k in keys) for item in value]
            assert len(seen) == len(set(seen)), f'{path} map keys repeat'
    elif kind == 'string':
        assert isinstance(value, str), path
        if 'enum' in schema:
            assert value in schema['enum'], f'{path}={value!r}'
        assert schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', 10**9), path
        if 'pattern' in schema:
            assert re.fullmatch(schema['pattern'], value), f'{path}={value!r}'
    elif kind == 'boolean':
        assert isinstance(value, bool), path
    elif kind == 'integer':
        assert isinstance(value, int), path


class WorldCrdTests(unittest.TestCase):
    def setUp(self):
        self.crd = yaml.safe_load(CRD.read_text())
        self.version = self.crd['spec']['versions'][0]
        self.schema = self.version['schema']['openAPIV3Schema']

    def test_api_rules(self):
        self.assertEqual(self.crd['spec']['group'], 'world.hangang.dev')
        self.assertEqual(self.version['name'], 'v1alpha1')
        self.assertIn('status', self.version['subresources'])
        self.assertIn('world', self.crd['spec']['names']['categories'])
        self.assertNotIn('x-kubernetes-preserve-unknown-fields', CRD.read_text())
        for path, node in walk(self.schema):
            if path in ('$.metadata', '$.apiVersion', '$.kind'):
                continue
            kind = node.get('type')
            if kind == 'string':
                self.assertTrue(any(bound in node for bound in ('maxLength', 'enum', 'format')), path)
            if kind == 'array':
                self.assertIn('maxItems', node, path)
                self.assertIn('x-kubernetes-list-type', node, path)
            if kind == 'object' and 'additionalProperties' in node:
                self.assertIn('maxProperties', node, path)
        status = self.schema['properties']['status']['properties']
        self.assertEqual(status['ancestors']['maxItems'], 16)
        rules = [rule['rule'] for _, node in walk(self.schema) for rule in node.get('x-kubernetes-validations', [])]
        self.assertTrue(any('namespaceDefault' in rule for rule in rules))
        self.assertTrue(any('exists_one' in rule for rule in rules))
        self.assertTrue(any("self.access == 'Public'" in rule for rule in rules))
        self.assertEqual(self.schema['properties']['spec']['properties']['access']['enum'], ['Protected', 'Public'])

    def test_examples_match_the_structural_schema(self):
        objects = [doc for doc in yaml.safe_load_all(EXAMPLE.read_text()) if doc['kind'] == 'ProtectionPolicy']
        self.assertEqual(len(objects), 3)
        for policy in objects:
            check(self.schema, policy)
            spec = policy['spec']
            self.assertEqual(bool(spec.get('namespaceDefault')), not spec.get('targetRefs'))
            # Mirror of the access CEL rule.
            if spec.get('access') == 'Public':
                self.assertIn('reason', spec['public'])
                self.assertFalse({'identity', 'authorization', 'network'} & spec.keys())
            else:
                self.assertTrue({'identity', 'authorization'} <= spec.keys())
                self.assertNotIn('public', spec)

    def test_invalid_shapes_are_refused_by_the_schema(self):
        policy = next(doc for doc in yaml.safe_load_all(EXAMPLE.read_text()) if doc['kind'] == 'ProtectionPolicy')
        for mutate in (
            lambda p: p['spec']['authorization']['pumgye']['actions'][0].update(method='get'),
            lambda p: p['spec'].update(failureMode='Open'),
            lambda p: p['spec']['targetRefs'][0].update(kind='Service'),
            lambda p: p['spec'].update(unknown=True),
            lambda p: p['spec']['authorization']['pumgye']['actions'].extend(
                [{'method': 'GET', 'action': 'again'}]),
            lambda p: p['spec'].update(access='Open'),
            lambda p: p['spec'].update(public={'paths': ['/x']}),
            lambda p: p['spec'].update(public={'reason': 'short'}),
            lambda p: p['spec'].update(public={'reason': 'long enough reason', 'paths': ['relative']}),
        ):
            broken = yaml.safe_load(yaml.safe_dump(policy))
            mutate(broken)
            with self.assertRaises(AssertionError):
                check(self.schema, broken)


if __name__ == '__main__':
    unittest.main()
