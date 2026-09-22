"""Owned UDP/HTTP3 container peers; no external services or production keys."""
import asyncio
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class H3Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)

    def quic_event_received(self, event):
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                body = os.environ['BACKEND_LABEL'].encode()
                self.http.send_headers(item.stream_id, [(b':status', b'200'), (b'content-length', str(len(body)).encode())])
                self.http.send_data(item.stream_id, body, end_stream=True)
                self.transmit()


class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        self.transport.sendto(os.environ['BACKEND_LABEL'].encode() + b':' + data, peer)


async def server():
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain('/fixture/tls.pem', '/fixture/tls.key')
    quic = await serve('0.0.0.0', 4443, configuration=config, create_protocol=H3Server)
    udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(Echo, local_addr=('0.0.0.0', 4444))
    print('ready', flush=True)
    try:
        await asyncio.Future()
    finally:
        quic.close()
        udp.close()


class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.pending = {}

    def quic_event_received(self, event):
        for item in self.http.handle_event(event):
            state = self.pending.get(getattr(item, 'stream_id', None))
            if state is None:
                continue
            if isinstance(item, HeadersReceived):
                state['status'] = dict(item.headers).get(b':status')
            elif isinstance(item, DataReceived):
                state['body'].extend(item.data)
            if getattr(item, 'stream_ended', False):
                self.pending.pop(item.stream_id)
                state['done'].set_result((state['status'], bytes(state['body'])))

    async def get(self):
        stream = self._quic.get_next_available_stream_id()
        done = asyncio.get_running_loop().create_future()
        self.pending[stream] = {'done': done, 'body': bytearray(), 'status': None}
        self.http.send_headers(stream, [(b':method', b'GET'), (b':scheme', b'https'), (b':authority', b'backend.example.test'), (b':path', b'/')], end_stream=True)
        self.transmit()
        return await asyncio.wait_for(done, 5)


def admin(method, path, document=None, revision=None):
    headers = {'Authorization': 'Bearer ' + Path('/fixture/admin-token').read_text().strip()}
    if revision is not None:
        headers['If-Match'] = '"' + str(revision) + '"'
    data = None
    if document is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(document).encode()
    request = urllib.request.Request('http://gateway:9000' + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def datagram_checks():
    labels = set()
    for index in range(12):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            chosen = None
            for size in (0, 32, 1400):
                message = bytes([index + 1]) * size
                client.sendto(message, ('gateway', 5444))
                data, _ = client.recvfrom(65535)
                label, actual = data.split(b':', 1)
                assert actual == message, 'UDP data changed or crossed client sessions'
                assert chosen in (None, label), 'UDP backend changed within a flow'
                chosen = label
                labels.add(label)
    assert labels == {b'backend-a', b'backend-b'}, 'UDP did not balance across backends'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(.3)
        client.sendto(b'x' * 2049, ('gateway', 5444))
        try:
            client.recvfrom(65535)
            raise AssertionError('oversize datagram was forwarded')
        except TimeoutError:
            pass
    # An invalid update must leave the active document and live relay intact.
    before = admin('GET', '/v1/config')
    invalid = json.loads(json.dumps(before))
    invalid['udp'][0]['backends'] = ['224.0.0.1:4443']
    try:
        admin('PUT', '/v1/config', invalid, before['revision'])
        raise AssertionError('multicast backend was accepted')
    except urllib.error.HTTPError as error:
        assert error.code == 422, error.code
    assert admin('GET', '/v1/config')['revision'] == before['revision']
    # Disable and re-enable through the same revision-checked API used by the UI.
    before['udp'][1]['enabled'] = False
    admin('PUT', '/v1/config', before, before['revision'])
    time.sleep(.15)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(.3)
        client.sendto(b'disabled', ('gateway', 5444))
        try:
            client.recvfrom(100)
            raise AssertionError('disabled route still forwarded')
        except TimeoutError:
            pass
    current = admin('GET', '/v1/config')
    current['udp'][1]['enabled'] = True
    admin('PUT', '/v1/config', current, current['revision'])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(b're-enabled', ('gateway', 5444))
        assert client.recvfrom(100)[0].endswith(b':re-enabled')
    print('UDP: 12 isolated flows, affinity, balancing, empty/1400-byte payloads, size limit, invalid reload retention, activation passed', flush=True)


async def quic_checks():
    labels = set()
    for _ in range(6):
        config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, server_name='backend.example.test')
        config.load_verify_locations('/fixture/tls.pem')
        async with asyncio.timeout(10):
            async with connect('gateway', 5443, configuration=config, create_protocol=H3Client) as client:
                responses = await asyncio.gather(*(client.get() for _ in range(3)))
                assert all(status == b'200' for status, _ in responses)
                assert len({body for _, body in responses}) == 1, 'QUIC flow changed backend'
                labels.add(responses[0][1])
                client.change_connection_id()
                client.request_key_update()
                status, body = await client.get()
                assert status == b'200' and body == responses[0][1]
    assert labels == {b'backend-a', b'backend-b'}, 'QUIC did not balance across flows'
    print('QUIC/HTTP3: verified TLS, 6 connections, 24 streams, multiplexing, backend affinity, CID rotation on unchanged tuple and key updates passed', flush=True)


if __name__ == '__main__':
    if sys.argv[1] == 'server':
        asyncio.run(server())
    else:
        datagram_checks()
        asyncio.run(quic_checks())
