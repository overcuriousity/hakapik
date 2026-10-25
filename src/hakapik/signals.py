"""Stop signals shared by the long-running commands (tail, fetch)."""

from __future__ import annotations

import asyncio
import contextlib
import signal

STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM)


@contextlib.contextmanager
def stop_on_signals(stop: asyncio.Event):
    """SIGINT/SIGTERM set ``stop``; a second one cancels the current task.

    Call from the task to cancel, inside a running loop. The handlers are
    installed inside the ``try``, so they are removed again on every exit,
    also when installing one of them fails.
    """
    loop = asyncio.get_running_loop()
    main = asyncio.current_task()

    def on_signal() -> None:
        if stop.is_set() and main is not None:
            main.cancel()
        stop.set()

    try:
        for sig in STOP_SIGNALS:
            loop.add_signal_handler(sig, on_signal)
        yield
    finally:
        for sig in STOP_SIGNALS:
            loop.remove_signal_handler(sig)  # False, not an error, if never added
