#!/usr/bin/env python3
"""Run SQL tests against one explicitly created, loopback-only PostgreSQL container."""
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    target=os.environ.get("HANGANG_PG_TEST_TARGET","config_store")
    if target not in {"config_store","sequenced_store","sequenced_export","receipt_release_workflow"}:
        raise ValueError("unsupported HANGANG_PG_TEST_TARGET")
    name="hangang-configstore-"+secrets.token_hex(6)
    password=secrets.token_hex(24)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0));port=listener.getsockname()[1]
    created=False
    with tempfile.TemporaryDirectory(prefix="hangang-pg-tls-") as directory:
        root=Path(directory);cert=root/"server.crt";key=root/"server.key"
        run("openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost,IP:127.0.0.1","-addext","basicConstraints=critical,CA:FALSE","-addext","extendedKeyUsage=serverAuth","-keyout",str(key),"-out",str(cert),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            run("docker","run","-d","--name",name,"-p",f"127.0.0.1:{port}:5432","-e",f"POSTGRES_PASSWORD={password}","-e","POSTGRES_DB=hangang","postgres:17-alpine",stdout=subprocess.DEVNULL)
            created=True
            for _ in range(120):
                ready=subprocess.run(["docker","exec",name,"pg_isready","-h","127.0.0.1","-U","postgres","-d","hangang"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                if ready.returncode==0:break
                time.sleep(.25)
            else:raise RuntimeError("PostgreSQL readiness timeout")
            run("docker","cp",str(cert),f"{name}:/tmp/server.crt",stdout=subprocess.DEVNULL)
            run("docker","cp",str(key),f"{name}:/tmp/server.key",stdout=subprocess.DEVNULL)
            run("docker","exec",name,"chown","postgres:postgres","/tmp/server.crt","/tmp/server.key")
            run("docker","exec",name,"chmod","600","/tmp/server.key")
            for sql in ["ALTER SYSTEM SET ssl_cert_file = '/tmp/server.crt'", "ALTER SYSTEM SET ssl_key_file = '/tmp/server.key'", "ALTER SYSTEM SET ssl = 'on'", "SELECT pg_reload_conf()"]:
                run("docker","exec",name,"psql","-U","postgres","-d","hangang","-v","ON_ERROR_STOP=1","-c",sql,stdout=subprocess.DEVNULL)
            time.sleep(.3)
            env={**os.environ,"HANGANG_TEST_POSTGRES_URL":f"postgresql://postgres:{password}@127.0.0.1:{port}/hangang","HANGANG_TEST_POSTGRES_TLS_URL":f"postgresql://postgres:{password}@localhost:{port}/hangang","HANGANG_TEST_POSTGRES_CA":str(cert),"HANGANG_TEST_POSTGRES_CONTAINER":name}
            command=["cargo","llvm-cov","--no-report"] if os.environ.get("HANGANG_PG_COVERAGE")=="1" else ["cargo","test"]
            run(*command,"--locked","--test",target,"--","postgres_","--test-threads=1","--nocapture","--include-ignored",env=env)
        finally:
            if created:run("docker","rm","--force",name,stdout=subprocess.DEVNULL)

if __name__=="__main__":main()
