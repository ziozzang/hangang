#!/usr/bin/env python3
"""Qualify the static image using only a newly created image and container."""
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

def run(*args,**kwargs):return subprocess.run(args,check=True,**kwargs)

def main():
    suffix=secrets.token_hex(6);image=f"hangang-static-check:{suffix}";name=f"hangang-static-check-{suffix}"
    built=created=False
    with tempfile.TemporaryDirectory(prefix="hangang-static-") as directory:
        root=Path(directory);root.chmod(0o755);data=root/"data";data.mkdir(mode=0o777);data.chmod(0o777)
        (data/"hangang.json").write_text('{"http":[],"tcp":[]}')
        try:
            run("docker","build","--network=none","--pull=false","-t",image,".",stdout=subprocess.DEVNULL)
            built=True
            # A non-root fixture owner must be able to remove the private
            # account directory afterward. Preserve non-root execution while
            # aligning bind-mount ownership; root runners keep the image UID.
            user_args=["--user",f"{os.getuid()}:{os.getgid()}"] if os.getuid()!=0 else []
            run("docker","run","-d","--name",name,*user_args,"--read-only","--network=none","--memory=256m","--cpus=1","-e","HANGANG_ADMIN_TOKEN=hangang-static-fixture-token","--mount",f"type=bind,source={data},target=/data",image,"--supervised","--config","/data/hangang.json","--threads","2","--lua-workers","1","--drain-seconds","2",stdout=subprocess.DEVNULL)
            created=True
            def await_log(text):
                for _ in range(100):
                    logs=run("docker","logs",name,capture_output=True,text=True)
                    if text in logs.stdout+logs.stderr:return
                    time.sleep(.1)
                raise RuntimeError(f"missing {text}: {logs.stdout}{logs.stderr}")
            await_log("hangang ready")
            run("docker","kill","--signal=HUP",name,stdout=subprocess.DEVNULL)
            await_log("gateway generation replaced")
            assert run("docker","inspect","--format","{{.State.Running}}",name,capture_output=True,text=True).stdout.strip()=="true"
            run("docker","exec",name,"/hangang","--config","/data/hangang.json","--check",stdout=subprocess.DEVNULL)
            run("docker","exec",name,"/hangang","--lua-sandbox-check",stdout=subprocess.DEVNULL)
            run("docker","stop","--time","10",name,stdout=subprocess.DEVNULL)
            assert run("docker","inspect","--format","{{.State.ExitCode}}",name,capture_output=True,text=True).stdout.strip()=="0"
            print("Static scratch image: non-root, read-only root, no network, check, live restart and clean shutdown passed")
        finally:
            if created:run("docker","rm","--force",name,stdout=subprocess.DEVNULL)
            if built:run("docker","image","rm",image,stdout=subprocess.DEVNULL)

if __name__=="__main__":main()
