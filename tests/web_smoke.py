#!/usr/bin/env python3
"""Run browser CRUD against an owned real gateway, with its embedded CSP assets."""
import http.client
import os
from pathlib import Path
import subprocess
import tempfile
import time
from smoke import BINARY, TOKEN, free_port

def main():
    with tempfile.TemporaryDirectory(prefix="hangang-web-") as directory:
        public,admin=free_port(),free_port()
        child=subprocess.Popen([str(BINARY),"--config",str(Path(directory)/"config.json"),"--listen",f"127.0.0.1:{public}","--admin",f"127.0.0.1:{admin}","--threads","2","--lua-workers","1"],env={**os.environ,"HANGANG_ADMIN_TOKEN":TOKEN},stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            for attempt in range(100):
                if child.poll() is not None:raise RuntimeError(child.stderr.read().decode())
                conn=http.client.HTTPConnection("127.0.0.1",admin,timeout=1)
                try:
                    conn.request("GET","/ui/")
                    if conn.getresponse().status==200:break
                except OSError:pass
                finally:conn.close()
                time.sleep(.05)
            else:raise RuntimeError("gateway readiness timeout")
            subprocess.run(["npx","playwright","test","tests/actual-server.spec.js"],cwd=Path(__file__).resolve().parents[1]/"web",env={**os.environ,"HANGANG_ACTUAL_BASE":f"http://127.0.0.1:{admin}","HANGANG_ACTUAL_TOKEN":TOKEN},check=True)
        finally:
            child.terminate()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.wait()
            child.stderr.close()

if __name__=="__main__":main()
