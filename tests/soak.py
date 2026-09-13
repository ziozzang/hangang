#!/usr/bin/env python3
"""Bounded mixed-traffic/config-churn stability test, not a capacity benchmark."""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
from pathlib import Path
import threading
import time
import smoke


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds",type=int,default=60)
    parser.add_argument("--output",type=Path,default=Path("tests/results/soak.json"))
    args=parser.parse_args()
    if args.seconds<5:parser.error("seconds must be at least 5")
    smoke.Smoke.setUpClass()
    gateway=smoke.Smoke
    stop=threading.Event();counts={"native_ok":0,"lua_ok":0,"lua_rejected":0,"unexpected":0};lock=threading.Lock();rss=[];writes=0
    def configuration(index):
        backends=[f"http://127.0.0.1:{server.server_port}" for server in gateway.backends]
        script="while true do end" if index%3==0 else "return nil"
        return {"http":[{"id":"lua","path_prefix":"/lua","lua":script,"backends":backends},{"id":"native","backends":backends[index%2:]+backends[:index%2]}]}
    def apply(index):
        revision=json.loads(gateway.request(gateway.admin,"GET","/v1/config",auth=True)[2])["revision"]
        status,*_=gateway.request(gateway.admin,"PUT","/v1/config",body=json.dumps(configuration(index)),headers={"If-Match":f'"{revision}"',"Content-Type":"application/json"},auth=True)
        assert status==200,f"configuration update returned {status}"
    def traffic(lua):
        conn=http.client.HTTPConnection("127.0.0.1",gateway.public,timeout=3)
        try:
            while not stop.is_set():
                try:
                    conn.request("GET","/lua" if lua else "/native")
                    response=conn.getresponse();response.read()
                    key=("lua_ok" if lua else "native_ok") if response.status==200 else "lua_rejected" if lua and response.status in (502,503) else "unexpected"
                except (OSError,http.client.HTTPException):key="unexpected";conn.close()
                with lock:counts[key]+=1
        finally:conn.close()
    started=time.monotonic()
    try:
        apply(1)
        with concurrent.futures.ThreadPoolExecutor(26) as pool:
            tasks=[pool.submit(traffic,index>=24) for index in range(26)]
            try:
                while time.monotonic()-started<args.seconds:
                    apply(writes);writes+=1
                    status=Path(f"/proc/{gateway.proc.pid}/status").read_text()
                    rss.append({"seconds":round(time.monotonic()-started,2),"rss_kib":int(next(line for line in status.splitlines() if line.startswith("VmRSS:")).split()[1])})
                    assert gateway.proc.poll() is None,"gateway exited"
                    time.sleep(.5)
            finally:stop.set()
            for task in tasks:task.result()
        assert counts["unexpected"]==0,counts
        assert counts["native_ok"]>1000 and counts["lua_ok"]>0 and counts["lua_rejected"]>0,counts
        warm=[sample["rss_kib"] for sample in rss if sample["seconds"]>=5]
        if warm:assert max(warm)-min(warm)<32*1024,"unexpected RSS growth over 32 MiB"
        result={"duration_seconds":round(time.monotonic()-started,2),"connections":26,"configuration_updates":writes,"counts":counts,"rss_samples":rss,"binary_sha256":hashlib.sha256(smoke.BINARY.read_bytes()).hexdigest(),"scope":"loopback stability under mixed Lua faults and live configuration churn; Python generator, not capacity"}
        args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps({key:value for key,value in result.items() if key!="rss_samples"},indent=2))
    finally:stop.set();gateway.tearDownClass()

if __name__=="__main__":main()
