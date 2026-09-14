#!/usr/bin/env python3
"""Run browser CRUD against an owned real gateway, with its embedded CSP assets."""
import http.client
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
from smoke import BINARY, TOKEN

def owned_ports():
    sockets = [socket.socket() for _ in range(3)]
    try:
        for item in sockets:item.bind(('127.0.0.1', 0))
        return [item.getsockname()[1] for item in sockets]
    finally:
        for item in sockets:item.close()

def main():
    with tempfile.TemporaryDirectory(prefix="hangang-web-") as directory:
        public,admin,fixture=owned_ports()
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
            # The ordinary browser suite may be running independently. Never
            # delete its trace directory or compete for its fixture listener.
            artifacts = tempfile.mkdtemp(prefix='hangang-web-smoke-artifacts-')
            try:
                subprocess.run(["npx","playwright","test","tests/actual-server.spec.js", "--output", artifacts],cwd=Path(__file__).resolve().parents[1]/"web",env={**os.environ,"HANGANG_UI_TEST_PORT":str(fixture),"HANGANG_ACTUAL_BASE":f"http://127.0.0.1:{admin}","HANGANG_ACTUAL_TOKEN":TOKEN},check=True)
            except BaseException:
                print(f'Owned browser failure artifacts retained at {artifacts}', flush=True)
                raise
            else:
                shutil.rmtree(artifacts)
        finally:
            child.terminate()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.wait()
            child.stderr.close()

if __name__=="__main__":main()
