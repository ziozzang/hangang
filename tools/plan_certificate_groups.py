#!/usr/bin/env python3
"""Plan certificate groups offline without contacting a CA or DNS provider."""
import argparse
import json
import ipaddress
from pathlib import Path


def group_domains(domains):
    if not isinstance(domains, list) or not 1 <= len(domains) <= 512:
        raise ValueError('domains must contain between 1 and 512 DNS names')
    groups, seen = {}, set()
    for raw in domains:
        if not isinstance(raw, str) or not raw or len(raw) > 253 or raw != raw.strip():
            raise ValueError('invalid domain name')
        name = raw.lower().rstrip('.')
        wildcard = name.startswith('*.')
        base = name[2:] if wildcard else name
        try:
            ipaddress.ip_address(base)
        except ValueError:
            pass
        else:
            raise ValueError('certificate groups require DNS names')
        labels = base.split('.')
        if len(labels) < 2 or any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') or any(char not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for char in label) for label in labels):
            raise ValueError('use a canonical ASCII DNS name; wildcards are allowed only as the first label')
        if name in seen:
            raise ValueError('duplicate domain name')
        seen.add(name)
        anchor = base[4:] if base.startswith('www.') and len(labels) >= 3 else base
        group = groups.setdefault(anchor, {'domain': anchor, 'domains': [], 'requires_dns01': False})
        group['domains'].append(name)
        group['requires_dns01'] |= wildcard
    return list(groups.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='issuer JSON containing domains, or a JSON array of domains')
    parser.add_argument('output', type=Path, help='new private JSON plan; no issuer is started')
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error('input and output must be separate files')
    try:
        source = json.loads(args.input.read_text())
        plan = {'groups': group_domains(source.get('domains') if isinstance(source, dict) else source)}
        # A plan contains only requested public DNS names, never provider credentials.
        from consolidate_listener_routes import write_private
        write_private(args.output, plan)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print('Planned', len(plan['groups']), 'certificate groups; no CA/DNS operation performed')


if __name__ == '__main__':
    main()
