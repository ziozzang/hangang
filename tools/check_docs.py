#!/usr/bin/env python3
"""Check local Markdown links against published (Git-index) paths."""
import posixpath
import re
import subprocess
from urllib.parse import unquote


def main():
    paths = set(subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')) - {''}
    failures = []
    checked = 0
    for name in sorted(paths):
        if not name.endswith('.md'):
            continue
        content = subprocess.check_output(['git', 'show', ':' + name]).decode()
        for match in re.finditer(r'\]\(([^\s)]+)(?:\s+"[^"]*")?\)', content):
            target = match[1].split('#', 1)[0]
            if not target or re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target):
                continue
            checked += 1
            target = unquote(target)
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
            if resolved not in paths and not any(p.startswith(resolved.rstrip('/') + '/') for p in paths):
                failures.append((name, match[1]))
    for name, target in failures:
        print(f'Broken published link: {name}: {target}')
    print(f'Checked {checked} local documentation links; failures: {len(failures)}')
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
