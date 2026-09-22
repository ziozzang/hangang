import json, socket, struct, sys, threading, time

vip, expected_peer, backend_mac1, backend_mac2, director_mac = sys.argv[1:6]
with open("/sys/class/net/eth0/address", encoding="ascii") as source:
    client_mac = source.read().strip().lower()
seen = {"tcp": [], "udp": []}
observed_macs = {"tcp": set(), "udp": set()}
capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
capture.bind(("eth0", 0)); capture.settimeout(0.1)
stop = threading.Event()
def capture_responses():
    while not stop.is_set():
        try: frame, packet_address = capture.recvfrom(65535)
        except socket.timeout: continue
        if packet_address[2] == 4:  # PACKET_OUTGOING: our own request/ACK
            continue
        if len(frame) >= 38 and frame[12:14] == b"\x08\x00" and frame[26:30] == socket.inet_aton(vip):
            if frame[30:34] == socket.inet_aton(expected_peer):
                transport = 14 + (frame[14] & 15) * 4
                if transport < 34 or len(frame) < transport + 4:
                    continue
                if frame[23] == 6 and struct.unpack_from("!H", frame, transport)[0] == 18080:
                    observed_macs["tcp"].add(frame[6:12].hex(":"))
                if frame[23] == 17 and struct.unpack_from("!H", frame, transport)[0] == 18081:
                    observed_macs["udp"].add(frame[6:12].hex(":"))
thread = threading.Thread(target=capture_responses, daemon=True); thread.start()
for _ in range(8):
    connection = socket.create_connection((vip, 18080), timeout=3)
    if connection.getpeername() != (vip, 18080): raise SystemExit("TCP peer was not the VIP")
    connection.sendall(b"x")
    seen["tcp"].append(json.loads(connection.recv(4096)))
    connection.close()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(3); udp.sendto(b"x", (vip, 18081))
    payload, peer = udp.recvfrom(4096)
    if peer != (vip, 18081): raise SystemExit("UDP peer was not the VIP")
    seen["udp"].append(json.loads(payload)); udp.close()
if any(item["peer"] != expected_peer for rows in seen.values() for item in rows):
    raise SystemExit("backend did not preserve client source address")
time.sleep(0.1); stop.set(); thread.join(timeout=1); capture.close()
if any(item["source"] != vip for rows in seen.values() for item in rows):
    raise SystemExit("backend response did not preserve VIP source")
expected_macs = {backend_mac1.lower(), backend_mac2.lower()}
for protocol in ("tcp", "udp"):
    roles = {item["role"] for item in seen[protocol]}
    if len(roles) < 2: raise SystemExit(f"IPVS did not distribute {protocol} across both backends: {roles}")
    backend_tx_macs = {mac.lower() for item in seen[protocol] for mac in item["tx_mac"]}
    if not expected_macs.issubset(backend_tx_macs):
        raise SystemExit(f"backend did not emit direct-return {protocol} packets")
    if observed_macs[protocol] != expected_macs:
        raise SystemExit(f"client packet capture did not prove direct {protocol} backend return: "
                         + repr({"expected": sorted(expected_macs), "observed": sorted(observed_macs[protocol]),
                                 "director": director_mac}))
if not expected_macs.issubset(observed_macs["tcp"] | observed_macs["udp"]):
    raise SystemExit("response Ethernet sources did not prove direct backend return: "
                     + repr({"expected": sorted(expected_macs), "observed": observed_macs,
                             "payload": sorted({item["mac"] for rows in seen.values() for item in rows}),
                             "director": director_mac, "client": client_mac}))
print(json.dumps({"passed": True, "tcp": seen["tcp"], "udp": seen["udp"],
                  "response_macs": {protocol: sorted(macs) for protocol, macs in observed_macs.items()}}))
