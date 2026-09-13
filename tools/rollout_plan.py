#!/usr/bin/env python3
"""Offline upgrade-wave checker. Does not contact nodes or execute deployments."""
import json
import re
import sys


class UnsafePlan(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise UnsafePlan(message)


def fields(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), f"invalid {label} fields")


def name(value):
    return type(value) is str and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", value)


def plan(document):
    fields(document, ['version', 'image_digest', 'max_parallel', 'roles', 'nodes'], 'manifest')
    require(type(document['version']) is int and document['version'] == 1, 'unsupported version')
    require(type(document['image_digest']) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', document['image_digest']), 'invalid image digest')
    parallel = document['max_parallel']
    require(type(parallel) is int and 1 <= parallel <= 256, 'invalid max_parallel')
    roles = document['roles']
    require(type(roles) is dict and 1 <= len(roles) <= 256, 'invalid roles')
    for role, policy in roles.items():
        require(name(role), 'invalid role name')
        fields(policy, ['min_ready', 'allow_outage', 'required_capabilities'], 'role')
        require(type(policy['min_ready']) is int and 0 <= policy['min_ready'] <= 4096, 'invalid min_ready')
        require(type(policy['allow_outage']) is bool, 'invalid allow_outage')
        require(policy['min_ready'] > 0 or policy['allow_outage'], 'zero floor needs explicit allow_outage')
        capabilities(policy['required_capabilities'])
    nodes = document['nodes']
    require(type(nodes) is list and 1 <= len(nodes) <= 4096, 'invalid nodes')
    ids = set()
    ready = dict.fromkeys(roles, 0)
    pending = []
    for node in nodes:
        fields(node, ['id', 'role', 'failure_domain', 'healthy', 'upgrade', 'revision', 'capabilities'], 'node')
        require(name(node['id']) and node['id'] not in ids, 'invalid or duplicate node id')
        ids.add(node['id'])
        require(name(node['role']) and node['role'] in roles and name(node['failure_domain']), 'invalid node role/domain')
        require(type(node['healthy']) is bool and type(node['upgrade']) is bool, 'invalid node flags')
        require(type(node['revision']) is int and 0 <= node['revision'] <= 2**53 - 1, 'invalid revision')
        capabilities(node['capabilities'])
        required = set(roles[node['role']]['required_capabilities'])
        capable = required <= set(node['capabilities'])
        # A reported-healthy node without its role's required features cannot
        # cover a peer during an upgrade, even when it is not itself a target.
        ready[node['role']] += int(node['healthy'] and capable)
        if node['upgrade']:
            require(node['healthy'], 'unhealthy target requires a separate recovery plan')
            require(capable, 'target lacks required capabilities')
            pending.append(node)
    for role, policy in roles.items():
        require(ready[role] >= policy['min_ready'], f'role {role} is already below readiness floor')
    pending.sort(key=lambda node: node['id'])
    waves = []
    while pending:
        selected, domains, unavailable = [], set(), dict.fromkeys(roles, 0)
        for node in pending:
            role = node['role']
            if len(selected) == parallel:
                break
            if node['failure_domain'] in domains or ready[role] - unavailable[role] - 1 < roles[role]['min_ready']:
                continue
            selected.append(node)
            domains.add(node['failure_domain'])
            unavailable[role] += 1
        require(selected, 'no wave satisfies the declared readiness floor and domain rule')
        waves.append([{'id': node['id'], 'expected_revision': node['revision']} for node in selected])
        selected_ids = {node['id'] for node in selected}
        pending = [node for node in pending if node['id'] not in selected_ids]
    return {'mode': 'offline_plan_only', 'image_digest': document['image_digest'], 'waves': waves,
            'gate_before_every_wave': 'Revalidate inventory, authority, revisions, compatibility and readiness; previous wave must be healthy at the exact target image.',
            'limitations': 'Input assertions are not observations. Only declared planned unavailability is modeled; correlated failure-domain loss, post-wave recovery, capacity, traffic steering, socket handoff, artifact compatibility and stream survival are not proven.'}


def capabilities(value):
    require(type(value) is list and len(value) <= 256 and all(name(item) for item in value), 'invalid capabilities')
    require(len(set(value)) == len(value), 'duplicate capability')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def main():
    try:
        data = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(data) <= 1024 * 1024, 'manifest exceeds 1 MiB')
        document = json.loads(data, object_pairs_hook=unique_object)
        print(json.dumps(plan(document), indent=2))
        return 0
    except (ValueError, TypeError, RecursionError):
        # No raw input or exception details: manifests must never become a log leak.
        print('Plan rejected: invalid manifest or unsafe readiness constraints.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
