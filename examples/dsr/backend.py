import json, socket, subprocess, sys, threading

role, vip, client_ip = sys.argv[1:4]
with open("/sys/class/net/eth0/address", encoding="ascii") as source:
    interface_mac = source.read().strip().lower()
outgoing_macs = set()

def observe_outgoing():
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    raw.bind(("eth0", 0))
    while True:
        frame, address = raw.recvfrom(65535)
        if address[2] == 4 and len(frame) >= 34 and frame[12:14] == b"\x08\x00":
            if frame[26:30] == socket.inet_aton(vip) and frame[30:34] == socket.inet_aton(client_ip):
                outgoing_macs.add(frame[6:12].hex(":"))
threading.Thread(target=observe_outgoing, daemon=True).start()
port_tcp, port_udp = 18080, 18081
subprocess.run(("ip", "addr", "add", vip + "/32", "dev", "lo"), check=True)

def serve_tcp():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((vip, port_tcp)); server.listen(32)
    while True:
        client, _ = server.accept()
        peer = client.getpeername()[0]
        client.recv(4096)
        body = json.dumps({"role": role, "peer": peer, "source": vip, "mac": interface_mac,
                           "tx_mac": sorted(outgoing_macs)}).encode()
        client.sendall(body); client.close()

def serve_udp():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((vip, port_udp))
    while True:
        _, address = server.recvfrom(4096)
        body = json.dumps({"role": role, "peer": address[0], "source": vip, "mac": interface_mac,
                           "tx_mac": sorted(outgoing_macs)}).encode()
        server.sendto(body, address)

threading.Thread(target=serve_udp, daemon=True).start()
serve_tcp()
