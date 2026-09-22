"""Fixture tests for multi-platform release staging."""

import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).parent))
import prepare_release  # noqa: E402


VERSION = "1.2.3"
PUBLIC_KEY = "A" * 43 + "="


class PrepareReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        (self.root / "Cargo.toml").write_text(
            f"[package]\nname = \"hangang\"\nversion = \"{VERSION}\"\n",
            encoding="utf-8",
        )
        (self.root / "LICENSE").write_text("license\n", encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def build_fixture(self, target, binaries):
        directory = self.root / "target" / target / "release"
        directory.mkdir(parents=True)
        for name in binaries:
            executable = directory / name
            executable.write_bytes(name.encode("ascii"))
            executable.chmod(0o755)

    def test_unsigned_macos_arm64_stages_archive_and_raw_binary_without_dsr_or_signing(self):
        target = "aarch64-apple-darwin"
        self.build_fixture(target, prepare_release.TARGETS[target][2])
        output = self.root / "out"

        with mock.patch.object(prepare_release, "ROOT", self.root), mock.patch.object(
            prepare_release, "run", return_value=f"hangang {VERSION}"
        ) as execute:
            prepare_release.prepare(None, output, target, unsigned=True)

        execute.assert_called_once_with(
            [self.root / "target" / target / "release" / "hangang", "--version"]
        )
        archive = output / f"hangang-v{VERSION}-darwin-arm64.tar.gz"
        self.assertEqual(
            set(path.name for path in output.iterdir()),
            {"hangang-aarch64-apple-darwin", archive.name, "SHA256SUMS"},
        )
        with tarfile.open(archive, "r:gz") as contents:
            names = contents.getnames()
        self.assertNotIn(f"hangang-v{VERSION}-darwin-arm64/hangang-dsr", names)
        self.assertIn(f"hangang-v{VERSION}-darwin-arm64/hangang-release-sign", names)
        checksums = (output / "SHA256SUMS").read_text(encoding="ascii").splitlines()
        self.assertEqual(len(checksums), 2)
        self.assertTrue(any(line.endswith("  " + archive.name) for line in checksums))
        self.assertTrue(any(line.endswith("  hangang-aarch64-apple-darwin") for line in checksums))
        sums = {name: checksum for checksum, name in (line.split("  ", 1) for line in checksums)}
        raw = output / "hangang-aarch64-apple-darwin"
        self.assertEqual(sums[archive.name], hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(sums[raw.name], hashlib.sha256(raw.read_bytes()).hexdigest())

    def test_signed_linux_arm64_keeps_manifest_key_and_checksums(self):
        target = "aarch64-unknown-linux-gnu"
        self.build_fixture(target, prepare_release.TARGETS[target][2])
        seed = self.root / "seed"
        seed.write_bytes(b"not-a-real-secret")
        output = self.root / "out"

        def fake_run(command):
            if command[1:] == ["--version"]:
                return f"hangang {VERSION}"
            if command[1:] == ["--public-key", seed.resolve()]:
                return PUBLIC_KEY
            payload, _, manifest = command[1:]
            data = json.loads(Path(payload).read_text(encoding="utf-8"))
            self.assertEqual(data["target"], target)
            Path(manifest).write_text("signature\n", encoding="ascii")
            return ""

        with mock.patch.object(prepare_release, "ROOT", self.root), mock.patch.object(
            prepare_release, "run", side_effect=fake_run
        ):
            prepare_release.prepare(seed, output, target)

        raw = output / "hangang-aarch64-unknown-linux-gnu"
        archive = output / f"hangang-v{VERSION}-linux-arm64.tar.gz"
        manifest = output / "hangang-aarch64-unknown-linux-gnu.manifest.json"
        self.assertTrue(manifest.is_file())
        self.assertEqual((output / "release-public-key.txt").read_text(encoding="ascii"), PUBLIC_KEY + "\n")
        sums = {
            name: checksum
            for checksum, name in (
                line.split("  ", 1)
                for line in (output / "SHA256SUMS").read_text(encoding="ascii").splitlines()
            )
        }
        self.assertEqual(sums[raw.name], hashlib.sha256(raw.read_bytes()).hexdigest())
        self.assertEqual(sums[archive.name], hashlib.sha256(archive.read_bytes()).hexdigest())
        with tarfile.open(archive, "r:gz") as contents:
            self.assertIn(f"hangang-v{VERSION}-linux-arm64/hangang-dsr", contents.getnames())

    def test_unsupported_target_is_rejected_before_accessing_the_seed(self):
        with self.assertRaisesRegex(ValueError, "unsupported target"):
            prepare_release.prepare(self.root / "missing-seed", self.root / "out", "wasm32-wasi")


if __name__ == "__main__":
    unittest.main()
