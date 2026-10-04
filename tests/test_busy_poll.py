import asyncio

import async_timeout

import picows
from tests.utils import TIMEOUT, WSServer, WSClient
from tests.fixtures import multiloop_event_loop_policy

event_loop_policy = multiloop_event_loop_policy()


class CountingBusyPoll(picows.WSBusyPoll):
    # Counts event loop iterations driven by busy polling
    def __init__(self):
        super().__init__()
        self.steps = 0

    def _step(self):
        self.steps += 1
        super()._step()


async def test_busy_poll_spins_until_stopped():
    busy_poll = CountingBusyPoll()
    assert not busy_poll.is_running

    # Starting twice must not create a second polling chain that stop() would leave behind
    busy_poll.start()
    busy_poll.start()
    assert busy_poll.is_running
    # Every loop iteration runs one step, even when the loop has nothing else to do
    await asyncio.sleep(0.1)
    assert busy_poll.steps > 100

    busy_poll.stop()
    busy_poll.stop()
    assert not busy_poll.is_running
    steps_after_stop = busy_poll.steps
    await asyncio.sleep(0.1)
    assert busy_poll.steps == steps_after_stop


async def test_busy_poll_delivers_messages():
    busy_poll = picows.WSBusyPoll()
    busy_poll.start()
    try:
        async with WSServer() as server:
            async with WSClient(server) as client:
                async with async_timeout.timeout(TIMEOUT):
                    for i in range(100):
                        msg = f"msg {i}"
                        client.transport.send(picows.WSMsgType.TEXT, msg.encode())
                        frame = await client.get_message()
                        assert frame.payload_as_utf8_text == msg
    finally:
        busy_poll.stop()
