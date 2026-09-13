#!/usr/bin/env python3
"""Listener handoff tests own every process, socket, and executable copy."""
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import smoke
from smoke import BINARY,TOKEN,Backend,TcpEcho,ThreadingTcpServer,free_port,recv_exact

class Restart(unittest.TestCase):
    def test_stable_supervisor_handoff_and_failed_candidate_recovery(self):
        with tempfile.TemporaryDirectory(prefix="hangang-restart-") as directory:
            root=Path(directory); executable=root/"hangang";shutil.copy2(BINARY,executable)
            backend=http.server.ThreadingHTTPServer(("127.0.0.1",0),Backend);backend.label="handoff";backend.daemon_threads=True
            echo=ThreadingTcpServer(("127.0.0.1",0),TcpEcho)
            for server in [backend,echo]: threading.Thread(target=server.serve_forever,daemon=True).start()
            ports=set()
            def allocate():
                value=free_port()
                while value in ports: value=free_port()
                ports.add(value);return value
            public,admin,tcp=allocate(),allocate(),allocate()
            state=root/"config.json"
            state.write_text(json.dumps({"http":[{"id":"main","backends":[f"http://127.0.0.1:{backend.server_port}"]}],"tcp":[{"id":"echo","listen":f"127.0.0.1:{tcp}","backends":[f"127.0.0.1:{echo.server_address[1]}"]}]}))
            with open(root/"log","w+") as log:
                child=subprocess.Popen([str(executable),"--supervised","--config",str(state),"--listen",f"127.0.0.1:{public}","--admin",f"127.0.0.1:{admin}","--threads","2","--lua-workers","1","--drain-seconds","3"],env={**os.environ,"HANGANG_ADMIN_TOKEN":TOKEN},stdout=log,stderr=log)
                stream=None
                def status():
                    code,_,body=smoke.Smoke.request(admin,"GET","/v1/status",auth=True)
                    self.assertEqual(code,200);return json.loads(body)
                def await_status(predicate):
                    for _ in range(150):
                        if child.poll() is not None: log.seek(0);self.fail(log.read())
                        try:
                            current=status()
                            if predicate(current): return current
                        except (OSError,http.client.HTTPException): pass
                        time.sleep(.05)
                    log.seek(0);self.fail("handoff timeout: "+log.read())
                try:
                    initial=await_status(lambda value:True)
                    self.assertTrue(initial["state"]["supervised"])
                    stream=socket.create_connection(("127.0.0.1",tcp),timeout=2)
                    stream.sendall(b"before");self.assertEqual(recv_exact(stream,6),b"before")
                    child.send_signal(signal.SIGHUP)
                    next_generation=await_status(lambda value:value["process_id"]!=initial["process_id"])
                    self.assertIsNone(child.poll())
                    stream.sendall(b"after");self.assertEqual(recv_exact(stream,5),b"after")
                    self.assertEqual(smoke.Smoke.request(public,"GET","/")[0],200)
                    stream.close();stream=None
                    # A candidate that cannot start must leave the old generation serving.
                    bad=root/"bad-candidate";bad.write_text("#!/bin/sh\nexit 42\n");bad.chmod(0o700);os.replace(bad,executable)
                    child.send_signal(signal.SIGHUP)
                    time.sleep(.7)
                    recovered=await_status(lambda value:not value["state"]["draining"])
                    self.assertEqual(recovered["process_id"],next_generation["process_id"])
                    self.assertEqual(smoke.Smoke.request(public,"GET","/")[0],200)
                    good=root/"good-candidate";shutil.copy2(BINARY,good);os.replace(good,executable)
                    code,_,_=smoke.Smoke.request(admin,"POST","/v1/lifecycle/restart",auth=True)
                    self.assertEqual(code,202)
                    final_generation=await_status(lambda value:value["process_id"]!=next_generation["process_id"])
                    # An unexpected serving-process death must be visible to the
                    # service manager as failure, rather than a clean shutdown.
                    os.kill(final_generation["process_id"],signal.SIGKILL)
                    self.assertNotEqual(child.wait(timeout=5),0)
                finally:
                    if stream: stream.close()
                    if child.poll() is None: child.terminate()
                    try:child.wait(timeout=10)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
                    for server in [backend,echo]:server.shutdown();server.server_close()

if __name__=="__main__":unittest.main(verbosity=2)
