#!/usr/bin/env python3
"""Docker HTTP/TCP discovery through an owned Unix fixture; no Docker daemon access."""
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from smoke import BINARY, TOKEN, Backend, TcpEcho, ThreadingTcpServer, free_port

class UnixHttp(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

class Inspect(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        state = self.server.state
        body = json.dumps({"State":{"Running":state["running"]},"NetworkSettings":{"Networks":{"edge":{"IPAddress":state["ip"],"GlobalIPv6Address":""}}}}).encode()
        self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*args): pass

class DockerRuntime(unittest.TestCase):
    def test_http_tcp_refresh_fail_closed_and_existing_stream_survival(self):
        servers=[]; child=None
        with tempfile.TemporaryDirectory(prefix="hangang-docker-") as directory:
            root=Path(directory)
            try:
                first=http.server.ThreadingHTTPServer(("127.0.0.1",0),Backend);first.label="first";servers.append(first)
                second=http.server.ThreadingHTTPServer(("127.0.0.2",first.server_port),Backend);second.label="second";servers.append(second)
                echo=ThreadingTcpServer(("127.0.0.1",0),TcpEcho);servers.append(echo)
                daemon=UnixHttp(str(root/"docker.sock"),Inspect);daemon.state={"running":True,"ip":"127.0.0.1"};servers.append(daemon)
                for server in servers: threading.Thread(target=server.serve_forever,daemon=True).start()
                public,admin,tcp=free_port(),free_port(),free_port()
                config={"http":[{"id":"container-http","backends":[f"docker://app/edge/{first.server_port}"]}],"tcp":[{"id":"container-tcp","listen":f"127.0.0.1:{tcp}","backends":[f"docker://app/edge/{echo.server_address[1]}"]}]}
                (root/"config.json").write_text(json.dumps(config))
                child=subprocess.Popen([str(BINARY),"--config",str(root/"config.json"),"--listen",f"127.0.0.1:{public}","--admin",f"127.0.0.1:{admin}","--docker-socket",str(root/"docker.sock"),"--threads","2","--lua-workers","1"],env={**os.environ,"HANGANG_ADMIN_TOKEN":TOKEN},stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                def request(port,path="/"):
                    conn=http.client.HTTPConnection("127.0.0.1",port,timeout=2)
                    try:
                        conn.request("GET",path,headers={"Authorization":f"Bearer {TOKEN}"}); response=conn.getresponse();return response.status,response.read()
                    finally:conn.close()
                def eventually(predicate):
                    deadline=time.monotonic()+6
                    while time.monotonic()<deadline:
                        if child.poll() is not None:self.fail(child.stderr.read().decode())
                        try:
                            if predicate():return
                        except (OSError,http.client.HTTPException):pass
                        time.sleep(.05)
                    self.fail("discovery convergence timeout")
                eventually(lambda:request(public)[0]==200)
                revision=json.loads(request(admin,"/v1/config")[1])["revision"]
                self.assertEqual(json.loads(request(public)[1])["backend"],"first")
                with socket.create_connection(("127.0.0.1",tcp),timeout=2) as existing:
                    existing.sendall(b"before");self.assertEqual(existing.recv(6),b"before")
                    daemon.state={"running":True,"ip":"127.0.0.2"}
                    eventually(lambda:json.loads(request(public)[1]).get("backend")=="second")
                    daemon.state={"running":False,"ip":"127.0.0.2"}
                    eventually(lambda:request(public)[0]==503)
                    with socket.create_connection(("127.0.0.1",tcp),timeout=2) as rejected:
                        rejected.sendall(b"new")
                        try:self.assertEqual(rejected.recv(3),b"")
                        except ConnectionResetError:pass
                    existing.sendall(b"after");self.assertEqual(existing.recv(5),b"after")
                    self.assertEqual(json.loads(request(admin,"/v1/config")[1])["revision"],revision)
                    daemon.state={"running":True,"ip":"127.0.0.1"}
                    eventually(lambda:request(public)[0]==200)
            finally:
                if child:
                    child.terminate()
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
                    child.stderr.close()
                for server in servers:server.shutdown();server.server_close()

if __name__=="__main__":unittest.main(verbosity=2)
