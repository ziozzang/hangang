#!/usr/bin/env python3
"""Listener handoff tests own every process, socket, and executable copy."""
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
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
            public,admin,tcp,workload=allocate(),allocate(),allocate(),allocate()
            # Owned CA and leaves exercise the workload descriptor through the
            # actual supervisor export/import path, including failed candidates.
            def openssl(*args):
                subprocess.run(["openssl", *map(str,args)],check=True,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            ca=root/"ca.pem"; ca_key=root/"ca.key"
            openssl("req","-x509","-newkey","rsa:2048","-nodes","-days","1",
                    "-subj","/CN=Owned workload CA","-addext","basicConstraints=critical,CA:TRUE",
                    "-addext","keyUsage=critical,keyCertSign,cRLSign","-keyout",ca_key,"-out",ca)
            identity="spiffe://example.test/restart"
            for name,usage,san in [("server","serverAuth","DNS:localhost"),
                                   ("client","clientAuth",f"URI:{identity}")]:
                key=root/f"{name}.key"; csr=root/f"{name}.csr"; cert=root/f"{name}.pem"
                openssl("req","-new","-newkey","rsa:2048","-nodes","-subj",f"/CN={name}",
                        "-keyout",key,"-out",csr)
                key.chmod(0o600)
                ext=root/f"{name}.ext"
                ext.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\nsubjectAltName={san}\n")
                openssl("x509","-req","-in",csr,"-CA",ca,"-CAkey",ca_key,
                        "-CAcreateserial","-days","1","-extfile",ext,"-out",cert)
            ca_key.chmod(0o600)
            context=ssl.create_default_context(cafile=str(ca))
            context.load_cert_chain(str(root/"client.pem"),str(root/"client.key"))
            def workload_request():
                with socket.create_connection(("127.0.0.1",workload),timeout=3) as raw:
                    with context.wrap_socket(raw,server_hostname="localhost") as tls:
                        tls.sendall(b"GET /workload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        response=http.client.HTTPResponse(tls);response.begin()
                        self.assertEqual(response.status,200)
                        self.assertIn(b"handoff",response.read())
            state=root/"config.json"
            state.write_text(json.dumps({"http":[{"id":"main","backends":[f"http://127.0.0.1:{backend.server_port}"]}],"tcp":[{"id":"echo","listen":f"127.0.0.1:{tcp}","backends":[f"127.0.0.1:{echo.server_address[1]}"]}]}))
            config=json.loads(state.read_text())
            config["workload_http"]=[{"id":"private","listen":f"127.0.0.1:{workload}","tls":{
                "cert_file":str(root/"server.pem"),"key_file":str(root/"server.key"),
                "client_ca_file":str(ca),"allowed_uri_sans":[identity]}}]
            config["http"].append({"id":"workload","path_prefix":"/workload","priority":10,
                "backends":[f"http://127.0.0.1:{backend.server_port}"],"access_mode":"protected",
                "workload_auth":{"listener_ids":["private"],"allowed_uri_sans":[identity]},
                "resource_policy":{"resource_id":"restart","principal":{"source":"workload"},
                                   "allow":[{"subjects":[identity],"methods":["GET"]}]}})
            state.write_text(json.dumps(config))
            with open(root/"log","w+") as log:
                child=subprocess.Popen([str(executable),"--supervised","--config",str(state),"--listen",f"127.0.0.1:{public}","--admin",f"127.0.0.1:{admin}","--threads","2","--lua-workers","1","--drain-seconds","10"],env={**os.environ,"HANGANG_ADMIN_TOKEN":TOKEN},stdout=log,stderr=log)
                stream=None
                held_workload=None
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
                    # Audit baseline, credentials and identities survive actual
                    # serving-generation replacement in the same local store.
                    credentials={"username":"audit-root","password":"owned audit fixture password"}
                    code,_,_=smoke.Smoke.request(admin,"POST","/v1/auth/bootstrap",json.dumps(credentials),{"Content-Type":"application/json"},auth=True)
                    self.assertEqual(code,201)
                    code,_,body=smoke.Smoke.request(admin,"POST","/v1/auth/login",json.dumps(credentials),{"Content-Type":"application/json"})
                    self.assertEqual(code,200)
                    account_headers={"Authorization":"Bearer "+json.loads(body)["token"],"Content-Type":"application/json"}
                    def account_audit():
                        code,_,body=smoke.Smoke.request(admin,"GET","/v1/audit/users",headers=account_headers)
                        self.assertEqual(code,200)
                        return json.loads(body)
                    code,_,body=smoke.Smoke.request(admin,"POST","/v1/users",json.dumps({"username":"audit-viewer","password":"owned viewer fixture password","role":"viewer"}),account_headers)
                    self.assertEqual(code,201)
                    audit_target=json.loads(body)["user"]["id"]
                    def config_operations():
                        code,_,body=smoke.Smoke.request(admin,"GET","/v1/config/operations",headers=account_headers)
                        self.assertEqual(code,200)
                        return json.loads(body)
                    operations_empty=config_operations()
                    self.assertEqual(operations_empty["records"],[])
                    code,_,body=smoke.Smoke.request(admin,"GET","/v1/config",headers=account_headers)
                    self.assertEqual(code,200)
                    candidate=json.loads(body)
                    config_headers={**account_headers,"If-Match":f'"{candidate["revision"]}"'}
                    code,_,_=smoke.Smoke.request(admin,"PUT","/v1/config",json.dumps(candidate),config_headers)
                    self.assertEqual(code,200)
                    operations_before=config_operations()
                    self.assertEqual(operations_before["authority_id"],operations_empty["authority_id"])
                    self.assertEqual([row["state"] for row in operations_before["records"]],["candidate_activated"])
                    first_operation_id=operations_before["records"][0]["id"]
                    candidate["revision"]+=1
                    config_headers["If-Match"]=f'"{candidate["revision"]}"'
                    code,_,_=smoke.Smoke.request(admin,"PUT","/v1/config",json.dumps(candidate),config_headers)
                    self.assertEqual(code,200)
                    unpruned=config_operations()
                    code,_,body=smoke.Smoke.request(admin,"POST","/v1/config/operations/prune",json.dumps({
                        "through_id":first_operation_id,"expected_latest_id":unpruned["latest_id"],
                        "expected_history_revision":unpruned["history_revision"]}),account_headers)
                    self.assertEqual(code,200)
                    self.assertEqual(json.loads(body)["record"]["action"],"config_operations_prune")
                    operations_before=config_operations()
                    self.assertEqual(operations_before["stored_records"],1)
                    self.assertGreater(operations_before["records"][0]["id"],first_operation_id)
                    self.assertTrue(operations_before["truncated"])
                    initial=status()
                    audit_before=account_audit()
                    self.assertEqual([row["action"] for row in audit_before["records"]],["baseline","bootstrap","create","config_operations_prune"])

                    workload_request()
                    self.assertEqual(initial["workload_materials"], [{"kind":"http","id":"private","ready":True}])
                    # File-only edits must change live admission without changing
                    # the shared configuration revision or requiring a restart.
                    original_ca=ca.read_bytes();ca.write_bytes(b"invalid client CA")
                    unavailable=await_status(lambda value: value["workload_materials"] == [{"kind":"http","id":"private","ready":False}])
                    self.assertEqual(unavailable["revision"],initial["revision"])
                    code,_,body=smoke.Smoke.request(admin,"GET","/metrics",auth=True)
                    self.assertEqual(code,200)
                    self.assertIn(b'hangang_workload_material_unavailable{kind="http"} 1',body)
                    with self.assertRaises((OSError,http.client.HTTPException)):
                        workload_request()
                    ca.write_bytes(original_ca)
                    restored=await_status(lambda value: value["workload_materials"] == [{"kind":"http","id":"private","ready":True}])
                    self.assertEqual(restored["revision"],initial["revision"])
                    workload_request()
                    stream=socket.create_connection(("127.0.0.1",tcp),timeout=2)
                    stream.sendall(b"before");self.assertEqual(recv_exact(stream,6),b"before")
                    held_workload=context.wrap_socket(socket.create_connection(("127.0.0.1",workload),timeout=3),server_hostname="localhost")
                    def held_request():
                        held_workload.sendall(b"GET /workload HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        response=http.client.HTTPResponse(held_workload);response.begin()
                        self.assertEqual(response.status,200);response.read();response.close()
                    held_request()
                    child.send_signal(signal.SIGHUP)
                    next_generation=await_status(lambda value:value["process_id"]!=initial["process_id"])
                    operations_after=config_operations()
                    self.assertEqual(operations_after["authority_id"],operations_before["authority_id"])
                    self.assertEqual(operations_after["records"],operations_before["records"])
                    audit_after=account_audit()
                    self.assertEqual(audit_after["records"],audit_before["records"])
                    self.assertEqual(audit_after["started_at_unix_ms"],audit_before["started_at_unix_ms"])
                    code,_,_=smoke.Smoke.request(admin,"PUT",f"/v1/users/{audit_target}",json.dumps({"enabled":False}),account_headers)
                    self.assertEqual(code,200)
                    audit_changed=account_audit()
                    self.assertEqual(audit_changed["records"][-1]["action"],"update")
                    self.assertEqual(audit_changed["records"][-1]["id"],audit_before["latest_id"]+1)

                    self.assertIsNone(child.poll())
                    workload_request()
                    held_request()
                    # The old generation is draining this existing connection.
                    # Its trust watcher must outlive the accept-loop shutdown.
                    ca.write_bytes(b"invalid CA during old generation drain")
                    await_status(lambda value: value["workload_materials"] == [{"kind":"http","id":"private","ready":False}])
                    held_workload.settimeout(2)
                    try:
                        self.assertEqual(held_workload.recv(1),b"")
                    except (ConnectionResetError,ssl.SSLError):
                        pass
                    held_workload.close();held_workload=None
                    ca.write_bytes(original_ca)
                    await_status(lambda value: value["workload_materials"] == [{"kind":"http","id":"private","ready":True}])
                    workload_request()
                    stream.sendall(b"after");self.assertEqual(recv_exact(stream,5),b"after")
                    self.assertEqual(smoke.Smoke.request(public,"GET","/")[0],200)
                    stream.close();stream=None
                    # A candidate that cannot start must leave the old generation serving.
                    bad=root/"bad-candidate";bad.write_text("#!/bin/sh\nexit 42\n");bad.chmod(0o700);os.replace(bad,executable)
                    child.send_signal(signal.SIGHUP)
                    time.sleep(.7)
                    recovered=await_status(lambda value:not value["state"]["draining"])
                    self.assertEqual(recovered["process_id"],next_generation["process_id"])
                    workload_request()
                    self.assertEqual(smoke.Smoke.request(public,"GET","/")[0],200)
                    good=root/"good-candidate";shutil.copy2(BINARY,good);os.replace(good,executable)
                    code,_,_=smoke.Smoke.request(admin,"POST","/v1/lifecycle/restart",auth=True)
                    self.assertEqual(code,202)
                    final_generation=await_status(lambda value:value["process_id"]!=next_generation["process_id"])
                    self.assertEqual(account_audit()["records"],audit_changed["records"])
                    self.assertEqual(config_operations()["records"],operations_before["records"])
                    workload_request()
                    # An unexpected serving-process death must be visible to the
                    # service manager as failure, rather than a clean shutdown.
                    os.kill(final_generation["process_id"],signal.SIGKILL)
                    self.assertNotEqual(child.wait(timeout=5),0)
                finally:
                    if stream: stream.close()
                    if held_workload: held_workload.close()
                    if child.poll() is None: child.terminate()
                    try:child.wait(timeout=10)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
                    for server in [backend,echo]:server.shutdown();server.server_close()

if __name__=="__main__":unittest.main(verbosity=2)
