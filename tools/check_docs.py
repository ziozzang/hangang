#!/usr/bin/env python3
"""Check published Markdown links and reference documentation conventions."""
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
        if name.startswith('docs/'):
            in_fence = False
            headings = []
            for line in content.splitlines():
                if re.match(r'^\s*(```|~~~)', line):
                    in_fence = not in_fence
                    continue
                if in_fence:
                    continue
                heading = re.match(r'^(#{1,6}) +(.+)', line)
                if heading:
                    headings.append((len(heading[1]), heading[2]))
                if '/' not in name[5:] and name not in ('docs/README.ko.md', 'docs/GLOSSARY.md'):
                    # A language switch may contain Korean; reference prose may not.
                    prose = re.sub(r'\[[^]]*\]\([^)]*\)', '', line)
                    if re.search(r'[가-힣]', prose):
                        failures.append((name, 'Korean prose belongs in docs/ko/'))
            if sum(level == 1 for level, _ in headings) != 1:
                failures.append((name, 'expected exactly one H1'))
            previous = 0
            for level, title in headings:
                if level > previous + 1:
                    failures.append((name, 'skipped heading level: ' + title))
                previous = level
            if name not in ('docs/README.md', 'docs/README.ko.md'):
                index = '../README.ko.md' if name.startswith('docs/ko/') else 'README.md'
                if '](' + index + ')' not in content:
                    failures.append((name, 'missing documentation index navigation'))
            if name.startswith('docs/ko/') and name != 'docs/ko/README.md':
                source = '../' + posixpath.basename(name)
                if '[English](' + source + ')' not in content:
                    failures.append((name, 'missing English source link'))
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
        print(f'Documentation error: {name}: {target}')
    print(f'Checked {checked} local documentation links; failures: {len(failures)}')
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
