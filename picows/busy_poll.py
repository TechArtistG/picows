import asyncio
from typing import Optional


class WSBusyPoll:
    """
    Keep an event loop from ever blocking in ``select``/``epoll_wait``.

    While running, a callback reschedules itself on every loop iteration, so the
    event loop always has ready work and polls sockets with a zero timeout instead
    of sleeping. Incoming data is then picked up without the wake-up latency of a
    blocked thread, at the cost of keeping one CPU core at 100%.

    One instance per event loop is enough, regardless of the number of connections.
    Methods must be called from the event loop thread.
    """

    def __init__(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        """
        :param loop: event loop to keep busy, defaults to the running loop.
        """
        self._loop = loop if loop is not None else asyncio.get_running_loop()
        self._handle: Optional[asyncio.Handle] = None

    @property
    def is_running(self) -> bool:
        """True between :any:`WSBusyPoll.start` and :any:`WSBusyPoll.stop`."""
        return self._handle is not None

    def start(self) -> None:
        """Start busy polling. Does nothing if it is already running."""
        if self._handle is None:
            self._handle = self._loop.call_soon(self._step)

    def stop(self) -> None:
        """Stop busy polling. Does nothing if it is not running."""
        if self._handle is not None:
            self._handle.cancel()
            self._handle = None

    def _step(self) -> None:
        self._handle = self._loop.call_soon(self._step)
