#!/usr/bin/env python3
"""Create an offline route-consolidation candidate; never contact a gateway."""
import argparse
import copy
import json
import os
from pathlib import Path
import tempfile

SELECTORS = {
    "host": None, "hosts": [], "host_regex": None, "path_prefix": None,
    "path_match": "prefix", "priority": 0, "headers": {}, "json": {},
}


def selector(route):
    return json.dumps({key: route.get(key, default) for key, default in SELECTORS.items()}, sort_keys=True)


def listeners(route):
    return route.get("listener_ids") or ["default"]


def exact_host(value):
    return isinstance(value, str) and bool(value) and not any(char in value for char in "*?:/[]")


def preserved_alternative(left, right):
    """Only recognize the known canonical-Host versus preserved-Host pattern."""
    for preserved, canonical in [(left, right), (right, left)]:
        if not preserved.get("preserve_host", False) or preserved.get("upstream_host") is not None:
            continue
        if canonical.get("preserve_host", False):
            continue
        override = canonical.get("upstream_host")
        if canonical.get("host_regex") is not None:
            continue
        host = canonical.get("host")
        aliases = canonical.get("hosts") or []
        if exact_host(host) and not aliases and override == host:
            return True
        if host is None and aliases and all(exact_host(alias) for alias in aliases) and override in aliases:
            return True
    return False


def merge(left, right, tls_listeners, prefer_preserve_host):
    ignored = {"id", "listener_ids"}
    host_changed = any(left.get(key) != right.get(key) for key in ("preserve_host", "upstream_host"))
    if host_changed:
        if not prefer_preserve_host or not preserved_alternative(left, right):
            return None
        ignored.update(("preserve_host", "upstream_host"))
    tls_changed = any(left.get(key) != right.get(key) for key in ("require_tls", "https_redirect_code"))
    strict = None
    if tls_changed:
        strict_routes = [route for route in (left, right) if route.get("require_tls", False)]
        relaxed_routes = [route for route in (left, right) if not route.get("require_tls", False)]
        if not strict_routes or not relaxed_routes:
            return None
        if any(not set(listeners(route)).issubset(tls_listeners) for route in relaxed_routes):
            return None
        strict = strict_routes[0]
        ignored.update(("require_tls", "https_redirect_code"))
    if {k: v for k, v in left.items() if k not in ignored} != {k: v for k, v in right.items() if k not in ignored}:
        return None
    merged = copy.deepcopy(left)
    merged["listener_ids"] = list(dict.fromkeys(listeners(left) + listeners(right)))
    if host_changed:
        merged["preserve_host"] = True
        merged["upstream_host"] = None
    if strict is not None:
        merged["require_tls"] = True
        merged["https_redirect_code"] = strict.get("https_redirect_code")
    return merged


def consolidate(config, *, prefer_preserve_host=False):
    if not isinstance(config, dict) or not isinstance(config.get("http"), list):
        raise ValueError("input must be a configuration with an HTTP route array")
    candidate = copy.deepcopy(config)
    tls_listeners = {
        listener["id"] for listener in config.get("public_http", [])
        if listener.get("enabled", True) and listener.get("certificates")
        # A trusted proxy can legitimately assert a plaintext original
        # scheme over TLS; then require_tls=false is not redundant.
        and not listener.get("trusted_proxy_cidrs")
    }
    output = []
    groups = {}
    merged_ids = []
    for route in config["http"]:
        if not isinstance(route, dict) or not isinstance(route.get("id"), str):
            raise ValueError("every HTTP route requires a string ID")
        key = selector(route)
        for index in groups.get(key, []):
            combined = merge(output[index], route, tls_listeners, prefer_preserve_host)
            if combined is not None:
                merged_ids.append({"retained": output[index]["id"], "removed": route["id"]})
                output[index] = combined
                break
        else:
            groups.setdefault(key, []).append(len(output))
            output.append(copy.deepcopy(route))
    conflicts = []
    for indices in groups.values():
        if len(indices) < 2:
            continue
        routes = [output[index] for index in indices]
        fields = set().union(*(set(route) for route in routes)) - {"id", "listener_ids"}
        differing = [field for field in sorted(fields) if len({json.dumps(route.get(field), sort_keys=True) for route in routes}) > 1]
        conflicts.append({"route_ids": [route["id"] for route in routes], "differing_fields": differing})
    candidate["http"] = output
    report = {"before": len(config["http"]), "after": len(output), "removed": len(merged_ids),
              "prefer_preserve_host": prefer_preserve_host, "merged": merged_ids, "conflicts": conflicts}
    return candidate, report


def write_private(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".hangang-route-candidate-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            os.chmod(temporary, 0o600)
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--prefer-preserve-host", action="store_true", help="explicitly unify recognized canonical/preserved Host alternatives using preserve_host=true")
    args = parser.parse_args()
    paths = [args.input.resolve(), args.output.resolve()]
    if args.report:
        paths.append(args.report.resolve())
    if len(set(paths)) != len(paths):
        parser.error("input, output and report must be separate files")
    try:
        candidate, report = consolidate(json.loads(args.input.read_text()), prefer_preserve_host=args.prefer_preserve_host)
        write_private(args.output, candidate)
        if args.report:
            write_private(args.report, report)
        print(json.dumps(report))
    except (OSError, ValueError) as error:
        parser.exit(1, f"route consolidation failed: {type(error).__name__}\n")


if __name__ == "__main__":
    main()
