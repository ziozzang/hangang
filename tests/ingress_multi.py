#!/usr/bin/env python3
"""Verify independent Services selected by host and longest Prefix, concurrently."""
import argparse
import concurrent.futures
import json
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--host-a', required=True)
parser.add_argument('--host-b', required=True)
args = parser.parse_args()
CASES = [
 (args.host_a, '/check', 'echo-'),
 (args.host_b, '/check', 'echo-b-'),
 (args.host_a, '/second/check', 'echo-b-'),
 (args.host_a, '/secondish', 'echo-'),
]
def check(i):
 host, path, prefix = CASES[i % len(CASES)]
 body = json.dumps({'request': i}).encode()
 req = urllib.request.Request('https://' + host + path + '?n=' + str(i), data=body,
     headers={'Content-Type': 'application/json', 'X-Multi-Test': str(i)}, method='POST')
 with urllib.request.urlopen(req, timeout=20) as r:
  d = json.load(r)
  pod = d['os']['hostname']
  assert r.status == 200 and pod.startswith(prefix), (i, pod)
  if prefix == 'echo-': assert not pod.startswith('echo-b-'), (i, pod)
  assert d['path'] == path and d['query'] == {'n': str(i)}
  assert d['body'] == body.decode() and d['method'] == 'POST'
  assert d['headers']['host'] == host and d['headers']['x-multi-test'] == str(i)
  assert d['headers']['x-forwarded-proto'] == 'https' and d['headers']['x-forwarded-port'] == '443'
  return pod
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
 pods = list(pool.map(check, range(100)))
print('100/100 concurrent requests PASS: host routing, path routing, Prefix boundary, Host/HTTPS/query/header/body')
print('Observed independent backend Pods:', ', '.join(sorted(set(pods))))
