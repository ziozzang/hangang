#!/usr/bin/env python3
"""Check published Markdown links and reference documentation conventions."""
import posixpath
import re
import subprocess
from urllib.parse import unquote


def translation_structure(content):
    """Compare non-translatable examples and the source document's structure."""
    headings, fences, table_rows = [], [], []
    fence = None
    block = []
    rows = 0
    for line in content.splitlines():
        marker = re.match(r'^\s*(```+|~~~+)(.*)$', line)
        if marker:
            if fence is None:
                fence = marker[1][0]
                block = [marker[2].strip()]
            elif marker[1][0] == fence:
                fences.append(tuple(block))
                fence = None
            else:
                block.append(line)
            continue
        if fence is not None:
            block.append(line)
            continue
        heading = re.match(r'^(#{1,6}) +', line)
        if heading:
            headings.append(len(heading[1]))
        if line.strip().startswith('|'):
            rows += 1
        elif rows:
            table_rows.append(rows)
            rows = 0
    if rows:
        table_rows.append(rows)
    if fence is not None:
        fences.append(('UNCLOSED', *block))
    return headings, fences, table_rows


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
        source = None
        if name.startswith('docs/ko/') and name.endswith('.md'):
            source = 'docs/' + posixpath.basename(name)
        elif name == 'docs/README.ko.md':
            source = 'docs/README.md'
        elif name == 'README.ko.md':
            source = 'README.md'
        elif name == 'examples/README.ko.md':
            source = 'examples/README.md'
        if source:
            if source not in paths:
                failures.append((name, 'missing English translation source: ' + source))
            else:
                original = subprocess.check_output(['git', 'show', ':' + source]).decode()
                expected = translation_structure(original)
                actual = translation_structure(content)
                for index, label in enumerate(('heading hierarchy', 'literal code examples', 'table rows')):
                    if expected[index] != actual[index]:
                        failures.append((name, 'translation differs from English source: ' + label))
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
