import copy
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from consolidate_listener_routes import consolidate


def route(id, listener, **changes):
    value = {"id": id, "listener_ids": [listener], "host": "app.example", "backends": ["http://origin:80"],
             "preserve_host": True, "upstream_host": None, "require_tls": False, "https_redirect_code": None}
    value.update(changes)
    return value


class ConsolidationTests(unittest.TestCase):
    def config(self, routes):
        return {"revision": 96, "http": routes, "public_http": [{"id": "tls", "certificates": [{}]}]}

    def test_equal_policies_preserve_first_id_route_order_and_listener_coverage(self):
        config = self.config([route("first", "default"), route("other", "default", host="other.example"), route("copy", "tls")])
        original = copy.deepcopy(config)
        candidate, report = consolidate(config)
        self.assertEqual(config, original)
        self.assertEqual([r["id"] for r in candidate["http"]], ["first", "other"])
        self.assertEqual(candidate["http"][0]["listener_ids"], ["default", "tls"])
        self.assertEqual(report["removed"], 1)
        self.assertEqual(candidate["revision"], 96)

    def test_host_changes_require_explicit_opt_in_and_recognized_exact_host(self):
        config = self.config([route("fixed", "default", preserve_host=False, upstream_host="app.example"), route("raw", "tls")])
        self.assertEqual(consolidate(config)[1]["removed"], 0)
        candidate, report = consolidate(config, prefer_preserve_host=True)
        self.assertEqual(report["removed"], 1)
        self.assertTrue(candidate["http"][0]["preserve_host"])
        self.assertIsNone(candidate["http"][0]["upstream_host"])
        for host, override in [("*.example", "app.example"), ("app.example", "other.example"), ("app.example", "app.example:443")]:
            invalid = self.config([route("fixed", "default", host=host, preserve_host=False, upstream_host=override), route("raw", "tls", host=host)])
            self.assertEqual(consolidate(invalid, prefer_preserve_host=True)[1]["removed"], 0)

    def test_multihost_quad_merges_only_with_reviewed_host_opt_in(self):
        routes = [route("first", "default", host=None, hosts=["app.example", "alias.example"], preserve_host=False, upstream_host="app.example"),
                  route("second", "tls", host=None, hosts=["app.example", "alias.example"], preserve_host=False, upstream_host="app.example"),
                  route("third", "direct", host=None, hosts=["app.example", "alias.example"]),
                  route("fourth", "direct-tls", host=None, hosts=["app.example", "alias.example"])]
        self.assertEqual(consolidate(self.config(routes))[1]["after"], 2)
        self.assertEqual(consolidate(self.config(routes), prefer_preserve_host=True)[1]["after"], 1)
        different = route("unrelated", "default", host=None, hosts=["different.example"])
        self.assertEqual(consolidate(self.config(routes + [different]), prefer_preserve_host=True)[1]["after"], 2)

    def test_tls_exception_requires_actual_tls_listener_and_retains_stricter_http_redirect(self):
        strict = route("http", "default", require_tls=True, https_redirect_code=308)
        relaxed = route("tls", "tls")
        candidate, report = consolidate(self.config([strict, relaxed]))
        self.assertEqual(report["removed"], 1)
        self.assertTrue(candidate["http"][0]["require_tls"])
        self.assertEqual(candidate["http"][0]["https_redirect_code"], 308)
        insecure = self.config([strict, route("copy", "direct")])
        self.assertEqual(consolidate(insecure)[1]["removed"], 0)
        delegated = self.config([strict, relaxed])
        delegated["public_http"][0]["trusted_proxy_cidrs"] = ["127.0.0.1/32"]
        self.assertEqual(consolidate(delegated)[1]["removed"], 0)

    def test_different_policy_or_functional_path_never_collapses_and_report_redacts_values(self):
        for change in [{"backends": ["http://different:80"]}, {"auth": {"token": "SECRET-SENTINEL"}}, {"country_policy": {"allow": ["KR"]}}, {"path_prefix": "/special/"}, {"priority": 100}]:
            candidate, report = consolidate(self.config([route("a", "default"), route("b", "tls", **change)]), prefer_preserve_host=True)
            self.assertEqual(len(candidate["http"]), 2)
            self.assertNotIn("SECRET-SENTINEL", json.dumps(report))

    def test_cli_output_is_private_and_input_cannot_be_overwritten(self):
        script = Path(__file__).with_name("consolidate_listener_routes.py")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            output = Path(directory) / "candidate.json"
            source.write_text(json.dumps(self.config([route("a", "default"), route("b", "tls")])))
            completed = subprocess.run([sys.executable, str(script), str(source), str(output)], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            rejected = subprocess.run([sys.executable, str(script), str(source), str(source)], capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)


if __name__ == "__main__":
    unittest.main()
