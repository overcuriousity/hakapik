"""The LogSource protocol and the factory choosing a client per log kind."""

from typing import Protocol

import httpx

from hakapik.ct.loglist import LogInfo


def base_url(url: str) -> str:
    """Return url with exactly one trailing slash."""
    return url.rstrip("/") + "/"


class LogSource(Protocol):
    info: LogInfo

    async def tree_size(self) -> int: ...

    async def entries(self, start: int, end: int) -> list[tuple[int, bytes, bytes]]: ...


def make_source(info: LogInfo, client: httpx.AsyncClient) -> LogSource:
    # Imported here: both client modules import base_url from this module.
    from hakapik.ct.rfc6962 import Rfc6962Log
    from hakapik.ct.static_ct import StaticCtLog

    if info.kind == "tiled":
        return StaticCtLog(info, client)
    return Rfc6962Log(info, client)
