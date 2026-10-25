"""The LogSource protocol and the factory choosing a client per log kind."""

from typing import Protocol

import httpx

from hakapik.ct.loglist import LogInfo
from hakapik.ct.rfc6962 import Rfc6962Log
from hakapik.ct.static_ct import StaticCtLog


class LogSource(Protocol):
    info: LogInfo

    async def tree_size(self) -> int: ...

    async def entries(self, start: int, end: int) -> list[tuple[int, bytes, bytes]]: ...


def make_source(info: LogInfo, client: httpx.AsyncClient) -> LogSource:
    if info.kind == "tiled":
        return StaticCtLog(info, client)
    if info.kind == "rfc6962":
        return Rfc6962Log(info, client)
    raise ValueError(f"unknown log kind {info.kind!r} for {info.log_id}")
