import asyncio
import base64
import hashlib
import struct

import async_timeout

import picows
from tests.utils import TIMEOUT
from tests.fixtures import multiloop_event_loop_policy

event_loop_policy = multiloop_event_loop_policy()

_WS_KEY = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


async def _read_masked_frame(reader: asyncio.StreamReader):
    b0, b1 = await reader.readexactly(2)
    assert b1 & 0x80, "client frames must be masked"
    length = b1 & 0x7F
    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]
    key = await reader.readexactly(4)
    masked = await reader.readexactly(length)
    return key, bytes(c ^ key[i % 4] for i, c in enumerate(masked))


async def _capture_client_frames(send_frames, num_frames: int):
    # Raw server: completes the upgrade and returns (masking key, unmasked payload) of each client frame
    frames = []
    done = asyncio.get_running_loop().create_future()

    async def handle(reader, writer):
        request = await reader.readuntil(b"\r\n\r\n")
        key = [line.split(b":", 1)[1].strip() for line in request.split(b"\r\n")
               if line.lower().startswith(b"sec-websocket-key:")][0]
        accept = base64.b64encode(hashlib.sha1(key + _WS_KEY).digest())
        writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
        for _ in range(num_frames):
            frames.append(await _read_masked_frame(reader))
        done.set_result(None)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        async with async_timeout.timeout(TIMEOUT):
            transport, _ = await picows.ws_connect(picows.WSListener, f"ws://127.0.0.1:{port}/")
            send_frames(transport)
            await done
            transport.disconnect()
    finally:
        server.close()
        await server.wait_closed()
    return frames


def _send_frames(transport: picows.WSTransport):
    # Both send paths: copying send() and in-place send_reuse_external_bytearray().
    for i in range(100):
        transport.send(picows.WSMsgType.BINARY, b"x" * i)
        buf = bytearray(14) + b"y" * i
        transport.send_reuse_external_bytearray(picows.WSMsgType.BINARY, buf, 14)


async def test_client_masking_keys_are_fresh_per_frame_and_connection():
    expected_payloads = [p for i in range(100) for p in (b"x" * i, b"y" * i)]

    frames1 = await _capture_client_frames(_send_frames, len(expected_payloads))
    frames2 = await _capture_client_frames(_send_frames, len(expected_payloads))

    for frames in (frames1, frames2):
        assert [payload for _, payload in frames] == expected_payloads

    keys1 = [key for key, _ in frames1]
    keys2 = [key for key, _ in frames2]
    # 400 random 32-bit keys collide with probability ~2e-5
    assert len(set(keys1)) == len(keys1)
    assert not set(keys1) & set(keys2)
