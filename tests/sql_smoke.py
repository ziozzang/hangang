#!/usr/bin/env python3
"""Two test-owned gateway processes coordinate through an isolated SQLite DB."""
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from smoke import BINARY, TOKEN, free_port

class SqlRuntime(unittest.TestCase):
    def test_two_instances_conflict_refresh_and_restart(self):
        with tempfile.TemporaryDirectory(prefix="hangang-sql-") as directory:
            root=Path(directory)
            database=os.environ.get("HANGANG_TEST_SHARED_DATABASE",f"sqlite:{root / 'shared.db'}")
            children=[]
            ports=set()
            def allocate():
                candidate=free_port()
                while candidate in ports: candidate=free_port()
                ports.add(candidate)
                return candidate
            admins=[]
            def call(port,method="GET",config=None,revision=None):
                conn=http.client.HTTPConnection("127.0.0.1",port,timeout=3)
                headers={"Authorization":f"Bearer {TOKEN}"}
                if config is not None: headers["Content-Type"]="application/json"
                if revision is not None: headers["If-Match"]=f'"{revision}"'
                conn.request(method,"/v1/config",None if config is None else json.dumps(config),headers)
                response=conn.getresponse(); payload=response.read(); conn.close()
                return response.status,payload
            def start(index):
                admin=allocate(); public=allocate()
                extra=(["--database-plaintext"] if database.startswith("redis://") else []) + (["--redis-key",os.environ["HANGANG_TEST_REDIS_KEY"]] if "HANGANG_TEST_REDIS_KEY" in os.environ else [])
                process=subprocess.Popen([str(BINARY),"--config",str(root/f"seed-{index}.json"),"--database",str(database),"--listen",f"127.0.0.1:{public}","--admin",f"127.0.0.1:{admin}","--threads","2","--lua-workers","1"]+extra,env={**os.environ,"HANGANG_ADMIN_TOKEN":TOKEN},stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                children.append(process)
                for _ in range(100):
                    if process.poll() is not None: self.fail(process.stderr.read().decode())
                    try:
                        if call(admin)[0]==200: return admin
                    except OSError: pass
                    time.sleep(.05)
                self.fail("server readiness timeout")
            try:
                admins=[start(0),start(1)]
                candidates=[{"http":[{"id":f"winner-{i}","backends":["http://127.0.0.1:1"]}]} for i in range(2)]
                with concurrent.futures.ThreadPoolExecutor(2) as pool:
                    futures=[pool.submit(call,p,"PUT",c,0) for p,c in zip(admins,candidates)]
                    results=[future.result() for future in futures]
                self.assertEqual(sorted(result[0] for result in results),[200,409])
                winning=json.loads(next(body for status,body in results if status==200))
                for _ in range(80):
                    snapshots=[json.loads(call(p)[1]) for p in admins]
                    if all(snapshot==winning for snapshot in snapshots): break
                    time.sleep(.05)
                self.assertEqual(snapshots,[winning,winning])
                children[0].terminate();children[0].wait(timeout=5)
                (root/"seed-2.json").write_text("invalid seed must be ignored after SQL bootstrap")
                restarted=start(2)
                self.assertEqual(json.loads(call(restarted)[1]),winning)
                # File changes are not a second writer in SQL mode.
                (root/"seed-1.json").write_text('{"http":[],"tcp":[]}')
                time.sleep(.7)
                self.assertEqual(json.loads(call(admins[1])[1]),winning)
            finally:
                for child in children:
                    if child.poll() is None: child.terminate()
                for child in children:
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired: child.kill();child.wait()
                    child.stderr.close()

if __name__=="__main__": unittest.main(verbosity=2)
