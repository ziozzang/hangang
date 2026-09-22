"""The publication guard rejects local-only paths in the Git index."""

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools' / 'check_publish.py'
SPEC = importlib.util.spec_from_file_location('check_publish', SCRIPT)
assert SPEC and SPEC.loader
check_publish = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_publish)


class PublishPolicyTests(unittest.TestCase):
    def test_local_only_paths(self):
        rejected = (
            'experiments/rust-lua/probe.rs',
            'perf/run.py',
            'docs/qualification/result.json',
            'docs/research/DSR_SCENARIOS.md',
            'docs/UPGRADE_PLAN.md',
            'docs/TLS_RESEARCH.md',
            'docs/POOL_DESIGN.md',
            'docs/POOL_THREATS.md',
            'docs/ENTERPRISE_DEPLOYMENT_2026-09-14.md',
            'docs/DECISIONS.md',
            'docs/DSR_LAB.md',
            'tools/dsr_probe.py',
            'tools/test_dsr_lab.py',
            'examples/tcp_member_bench.rs',
            'examples/canary/probe.py',
        )
        for path in rejected:
            with self.subTest(path=path):
                self.assertTrue(check_publish.is_local_only(path))

    def test_public_similar_paths(self):
        allowed = (
            'docs/DEPLOYMENT.md',
            'docs/CONFIG_PUBLICATION.md',
            'docs/README.md',
            'docs/openapi.json',
            'examples/fleet-observer/run.py',
            'examples/tcp_member.rs',
            'tools/rollout_plan.py',
            'tools/check_publish.py',
            'tests/test_publish_policy.py',
        )
        for path in allowed:
            with self.subTest(path=path):
                self.assertFalse(check_publish.is_local_only(path))

    def test_staged_local_path_rejected_without_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            subprocess.run(['git', 'init', '-q'], cwd=directory, check=True)
            path = directory / 'docs' / 'qualification' / 'receipt.json'
            path.parent.mkdir(parents=True)
            sentinel = 'PRIVATE-TEST-SENTINEL-DO-NOT-PRINT'
            path.write_text(sentinel)
            subprocess.run(['git', 'add', 'docs/qualification/receipt.json'], cwd=directory, check=True)
            result = subprocess.run(
                ['python3', str(SCRIPT)], cwd=directory, text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn('local-only path', result.stdout)
            self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_forced_ignored_operator_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            subprocess.run(['git', 'init', '-q'], cwd=directory, check=True)
            (directory / '.gitignore').write_text('/operator.env\n')
            (directory / 'operator.env').write_text('PRIVATE-OPERATOR-CONTENT\n')
            subprocess.run(['git', 'add', '-f', '.gitignore', 'operator.env'], cwd=directory, check=True)
            result = subprocess.run(['python3', str(SCRIPT)], cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('operator.env', result.stdout)
            self.assertNotIn('PRIVATE-OPERATOR-CONTENT', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
