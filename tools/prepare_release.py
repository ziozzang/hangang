#!/usr/bin/env python3
"""Stage reproducible native release assets without publishing them."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parent.parent
TARGET = "x86_64-unknown-linux-gnu"
COMMON_BINARIES = (
    "hangang",
    "hangang-acme-issuer",
    "hangang-admin-gateway",
    "hangang-auth-bridge",
    "hangang-dsr",
    "hangang-network-bridge",
    "hangang-release-sign",
)
TARGETS = {
    "x86_64-unknown-linux-gnu": ("linux", "amd64", COMMON_BINARIES),
    "aarch64-unknown-linux-gnu": ("linux", "arm64", COMMON_BINARIES),
    "x86_64-apple-darwin": ("darwin", "amd64", tuple(name for name in COMMON_BINARIES if name != "hangang-dsr")),
    "aarch64-apple-darwin": ("darwin", "arm64", tuple(name for name in COMMON_BINARIES if name != "hangang-dsr")),
}


def run(command: list[str | Path]) -> str:
    result = subprocess.run(
        [str(part) for part in command],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def add_file(archive: tarfile.TarFile, source: Path, name: str, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = source.stat().st_size
    info.mode = mode
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    with source.open("rb") as stream:
        archive.addfile(info, stream)


def prepare(seed: Path | None, output: Path, target: str, *, unsigned: bool = False) -> None:
    try:
        platform, architecture, binaries = TARGETS[target]
    except KeyError:
        raise ValueError(f"unsupported target: {target}") from None
    if unsigned:
        if seed is not None:
            raise ValueError("unsigned staging must not use a signing seed")
    elif seed is None:
        raise ValueError("signing seed is required unless --unsigned is used")
    elif not seed.is_file() or seed.is_symlink():
        raise ValueError("signing seed must be an existing regular file")
    if seed is not None:
        seed = seed.resolve()
    output = output.resolve()
    if seed is not None and (output == seed or output in seed.parents or seed in output.parents):
        raise ValueError("output directory must be separate from the signing seed")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("output directory must be empty")

    package = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    version = package["package"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError(f"release version must be stable MAJOR.MINOR.PATCH: {version}")
    build_dir = ROOT / "target" / target / "release"
    executables = {name: build_dir / name for name in binaries}
    for name, path in executables.items():
        if not path.is_file() or not path.stat().st_mode & 0o111:
            raise ValueError(f"missing executable release build: {path}")
    license_file = ROOT / "LICENSE"
    if not license_file.is_file():
        raise ValueError("LICENSE is missing")
    reported = run([executables["hangang"], "--version"])
    if reported != f"hangang {version}":
        raise ValueError(f"gateway version mismatch: expected hangang {version}, got {reported!r}")

    signer = executables["hangang-release-sign"]
    public_key = None
    if not unsigned:
        public_key = run([signer, "--public-key", seed])
        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", public_key):
            raise ValueError("signer returned an invalid public key")
        pinned_key = ROOT / "release-public-key.txt"
        if pinned_key.exists() and pinned_key.read_text(encoding="utf-8").strip() != public_key:
            raise ValueError("signing seed does not match release-public-key.txt")

    output.mkdir(parents=True, exist_ok=True)
    basename = f"hangang-{target}"
    artifact = output / basename
    shutil.copyfile(executables["hangang"], artifact)
    artifact.chmod(0o755)

    archive_path = output / f"hangang-v{version}-{platform}-{architecture}.tar.gz"
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                directory = f"hangang-v{version}-{platform}-{architecture}"
                for name, path in executables.items():
                    add_file(archive, path, f"{directory}/{name}", 0o755)
                add_file(archive, license_file, f"{directory}/LICENSE", 0o644)

    if not unsigned:
        payload = {
            "version": version,
            "target": target,
            "artifact_url": f"https://github.com/ziozzang/hangang/releases/download/v{version}/{basename}",
            "size": artifact.stat().st_size,
            "sha256": digest(artifact),
        }
        manifest = output / f"{basename}.manifest.json"
        # The unsigned payload is temporary; the signing helper is the only seed reader.
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=output, prefix=".release-payload-", suffix=".json", delete=False
        ) as temporary:
            payload_path = Path(temporary.name)
            json.dump(payload, temporary, separators=(",", ":"), ensure_ascii=True)
        try:
            run([signer, payload_path, seed, manifest])
        finally:
            payload_path.unlink(missing_ok=True)
        (output / "release-public-key.txt").write_text(public_key + "\n", encoding="ascii")
    assets = sorted(path for path in output.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    (output / "SHA256SUMS").write_text(
        "".join(f"{digest(path)}  {path.name}\n" for path in assets), encoding="ascii"
    )
    print(f"Staged {len(assets) + 1} assets in {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    signing = parser.add_mutually_exclusive_group(required=True)
    signing.add_argument("--signing-seed-file", type=Path)
    signing.add_argument(
        "--unsigned",
        action="store_true",
        help="stage CI artifacts without a manifest or release public key",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target", default=TARGET)
    args = parser.parse_args()
    try:
        prepare(args.signing_seed_file, args.output, args.target, unsigned=args.unsigned)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        print(f"prepare_release: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
