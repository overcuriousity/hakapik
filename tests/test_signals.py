import asyncio
import os
import signal

import pytest

from hakapik.signals import stop_on_signals


async def test_first_signal_sets_stop_second_cancels():
    stop = asyncio.Event()

    async def body():
        with stop_on_signals(stop):
            os.kill(os.getpid(), signal.SIGTERM)
            await stop.wait()
            os.kill(os.getpid(), signal.SIGINT)
            await asyncio.Event().wait()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(asyncio.create_task(body()), timeout=2)
    assert stop.is_set()


async def test_handlers_removed_when_installing_one_fails(monkeypatch):
    loop = asyncio.get_running_loop()
    real_add = loop.add_signal_handler

    def add(sig, cb):
        if sig == signal.SIGTERM:
            raise RuntimeError("cannot install")
        real_add(sig, cb)

    monkeypatch.setattr(loop, "add_signal_handler", add)
    with pytest.raises(RuntimeError):
        with stop_on_signals(asyncio.Event()):
            pass
    # SIGINT's handler, installed first, was removed again.
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
