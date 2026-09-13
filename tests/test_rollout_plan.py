import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('rollout_plan', Path(__file__).resolve().parents[1] / 'tools/rollout_plan.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    return {'version': 1, 'image_digest': 'sha256:' + 'a' * 64, 'max_parallel': 4,
            'roles': {'http': {'min_ready': 1, 'allow_outage': False, 'required_capabilities': ['http']}},
            'nodes': [{'id': f'n{i}', 'role': 'http', 'failure_domain': f'host{i}', 'healthy': True,
                       'upgrade': True, 'revision': 7, 'capabilities': ['http']} for i in range(3)]}


class RolloutSafety(unittest.TestCase):
    def test_minimum_preserved_and_every_node_once(self):
        result = m.plan(fixture())
        self.assertEqual([len(w) for w in result['waves']], [2, 1])
        self.assertEqual([n['id'] for w in result['waves'] for n in w], ['n0', 'n1', 'n2'])
        self.assertTrue(all(n['expected_revision'] == 7 for w in result['waves'] for n in w))

    def test_different_roles_do_not_supply_redundancy(self):
        d = fixture()
        for i, node in enumerate(d['nodes']):
            node['role'] = f'role{i}'
        d['roles'] = {node['role']: copy.deepcopy(d['roles']['http']) for node in d['nodes']}
        with self.assertRaises(m.UnsafePlan):
            m.plan(d)

    def test_shared_failure_domain_serializes(self):
        d = fixture()
        for node in d['nodes']:
            node['failure_domain'] = 'one-host'
        self.assertEqual([len(w) for w in m.plan(d)['waves']], [1, 1, 1])

    def test_unhealthy_nontarget_does_not_count_as_spare(self):
        d = fixture()
        d['nodes'][2].update(healthy=False, upgrade=False)
        self.assertEqual([len(w) for w in m.plan(d)['waves']], [1, 1])
        d['roles']['http']['min_ready'] = 3
        with self.assertRaises(m.UnsafePlan):
            m.plan(d)

    def test_explicit_outage_required(self):
        d = fixture()
        d['nodes'] = d['nodes'][:1]
        d['roles']['http']['min_ready'] = 0
        with self.assertRaises(m.UnsafePlan):
            m.plan(d)
        d['roles']['http']['allow_outage'] = True
        self.assertEqual(len(m.plan(d)['waves']), 1)

    def test_incompatible_target_rejected(self):
        d = fixture()
        d['nodes'][1]['capabilities'] = []
        with self.assertRaises(m.UnsafePlan):
            m.plan(d)

    def test_incompatible_healthy_nontarget_is_not_readiness_spare(self):
        d = fixture()
        d['nodes'][2].update(upgrade=False, capabilities=[])
        d['roles']['http']['min_ready'] = 2
        with self.assertRaises(m.UnsafePlan):
            m.plan(d)

    def test_order_deterministic(self):
        d = fixture()
        expected = m.plan(d)
        d['nodes'].reverse()
        self.assertEqual(m.plan(d), expected)

    def test_invalid_manifest_rejected(self):
        for mutate in [lambda d: d.update(max_parallel=True), lambda d: d.update(version=True),
                       lambda d: d.update(image_digest='latest'), lambda d: d.update(extra=1),
                       lambda d: d['nodes'].append(copy.deepcopy(d['nodes'][0])),
                       lambda d: d['nodes'][0].update(revision=-1),
                       lambda d: d['nodes'][0].update(healthy=False)]:
            with self.subTest(mutate=mutate):
                d = fixture()
                mutate(d)
                with self.assertRaises(m.UnsafePlan):
                    m.plan(d)

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaises(m.UnsafePlan):
            m.json.loads('{"version":1,"version":1}', object_pairs_hook=m.unique_object)


if __name__ == '__main__':
    unittest.main()
