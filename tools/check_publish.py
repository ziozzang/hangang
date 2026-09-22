#!/usr/bin/env python3
"""Inspect the Git index without printing secret values or file contents."""
import argparse
import re
import shlex
import subprocess
from pathlib import Path

PATTERNS = {
    'private key': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'),
    'GitHub credential': re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b'),
    'AWS access key': re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'Google API key': re.compile(rb'\bAIza[A-Za-z0-9_-]{35}\b'),
    'Slack token': re.compile(rb'\bxox[baprs]-[A-Za-z0-9-]{20,}\b'),
}

LOCAL_ONLY_PREFIXES = (
    'experiments/', 'perf/', 'docs/qualification/', 'docs/research/',
    'examples/canary/',
)
LOCAL_ONLY_FILES = {'docs/DECISIONS.md', 'docs/DSR_LAB.md', 'tools/test_dsr_lab.py'}
LOCAL_ONLY_DOC_SUFFIXES = ('_PLAN.md', '_RESEARCH.md', '_DESIGN.md', '_THREATS.md')
LOCAL_ONLY_DEPLOYMENT = re.compile(r'^docs/[^/]*DEPLOYMENT_20[^/]*\.md$')


def is_local_only(path):
    """Return whether a Git-index path is private working material."""
    if path in LOCAL_ONLY_FILES or path.startswith(LOCAL_ONLY_PREFIXES):
        return True
    if path.startswith('docs/') and '/' not in path[5:]:
        if path.endswith(LOCAL_ONLY_DOC_SUFFIXES) or LOCAL_ONLY_DEPLOYMENT.fullmatch(path):
            return True
    return ((path.startswith('tools/dsr_') and path.endswith('.py') and '/' not in path[6:])
            or (path.startswith('examples/') and path.endswith('_bench.rs') and '/' not in path[9:]))


def known_values(path):
    values = []
    if path is None:
        return values
    for line in Path(path).read_text().splitlines():
        match = re.match(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$', line)
        if not match:
            continue
        try:
            parts = shlex.split(match[2], comments=True)
        except ValueError:
            continue
        if len(parts) == 1 and len(parts[0]) >= 12:
            # No shell evaluation. Compare literal values; never print them.
            values.append(parts[0].encode())
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--secrets-file', type=Path, help='optional local env file; never copied into Git')
    args = parser.parse_args()
    secrets = known_values(args.secrets_file)
    indexed = subprocess.check_output(['git', 'ls-files', '-z'])
    paths = indexed.split(b'\0')
    ignored_result = subprocess.run(
        ['git', 'check-ignore', '--no-index', '--stdin', '-z'],
        input=indexed, capture_output=True, check=False,
    )
    if ignored_result.returncode not in (0, 1):
        raise SystemExit('Cannot verify ignored paths; publication check stopped')
    ignored = set(ignored_result.stdout.split(b'\0')) - {b''}
    failures = []
    checked = 0
    for raw in filter(None, paths):
        name = raw.decode('utf-8', errors='surrogateescape')
        checked += 1
        if is_local_only(name) or raw in ignored:
            failures.append((name, 'local-only path'))
            continue
        content = subprocess.check_output(['git', 'show', ':' + name])
        for label, pattern in PATTERNS.items():
            if pattern.search(content):
                failures.append((name, label))
        if any(value in content for value in secrets):
            failures.append((name, 'exact local environment value'))
    for name, label in failures:
        print(f'BLOCKED {name!r}: {label}; value redacted')
    print(f'Checked {checked} staged files; findings: {len(failures)}')
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
