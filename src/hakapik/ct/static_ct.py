"""HTTP client for tiled (static-CT) Certificate Transparency logs."""

import base64

import httpx

from hakapik.ct._retry import retry_get
from hakapik.ct.leaf import LeafError, parse_tile_leaf
from hakapik.ct.loglist import LogInfo
from hakapik.ct.source import base_url

TILE_WIDTH = 256


def parse_checkpoint(text: str) -> tuple[int, bytes]:
    """Return (tree size, root hash) from a signed checkpoint note."""
    lines = text.split("\n")
    return int(lines[1]), base64.b64decode(lines[2])


def tile_path(index: int, partial: int | None) -> str:
    """Path of data tile `index`; `partial` is the width of a partial tile."""
    groups = []
    while True:
        groups.append(f"{index % 1000:03d}")
        index //= 1000
        if index == 0:
            break
    groups.reverse()
    enc = "/".join([f"x{g}" for g in groups[:-1]] + [groups[-1]])
    path = f"tile/data/{enc}"
    return path if partial is None else f"{path}.p/{partial}"


def _split_tile(data: bytes) -> list[bytes]:
    buf = memoryview(data)
    leaves, off = [], 0
    while off < len(buf):
        rec, nxt = parse_tile_leaf(buf, off)
        if isinstance(rec, LeafError) and nxt == len(buf):
            raise RuntimeError(f"cannot delimit tile leaf at offset {off}: {rec.reason}")
        leaves.append(data[off:nxt])
        off = nxt
    return leaves


class StaticCtLog:
    def __init__(self, info: LogInfo, client: httpx.AsyncClient):
        self.info = info
        self._client = client
        self._base = base_url(info.monitoring_url)

    async def tree_size(self) -> int:
        resp = await retry_get(self._client, f"{self._base}checkpoint")
        return parse_checkpoint(resp.text)[0]

    async def _tile(self, n: int, tree_size: int) -> list[bytes]:
        width = min(TILE_WIDTH, tree_size - TILE_WIDTH * n)
        partial = width if width < TILE_WIDTH else None
        resp = await retry_get(self._client, self._base + tile_path(n, partial))
        leaves = _split_tile(resp.content)
        if len(leaves) != width:
            raise RuntimeError(f"tile {n} holds {len(leaves)} leaves, expected {width}")
        return leaves

    async def entries(self, start: int, end: int) -> list[tuple[int, bytes, bytes]]:
        """Fetch entries start..end inclusive, clamped to the tree size."""
        size = await self.tree_size()
        end = min(end, size - 1)
        out: list[tuple[int, bytes, bytes]] = []
        if start > end:
            return out
        for n in range(start // TILE_WIDTH, end // TILE_WIDTH + 1):
            leaves = await self._tile(n, size)
            for j, leaf in enumerate(leaves):
                i = TILE_WIDTH * n + j
                if start <= i <= end:
                    out.append((i, leaf, b""))
        return out

    async def index_at(self, ts_ms: int) -> int:
        """First index whose timestamp is >= ts_ms, or tree_size if none."""
        size = await self.tree_size()
        cached: tuple[int, list[bytes]] | None = None
        lo, hi = 0, size
        while lo < hi:
            mid = (lo + hi) // 2
            n = mid // TILE_WIDTH
            if cached is None or cached[0] != n:
                cached = (n, await self._tile(n, size))
            leaf = cached[1][mid - TILE_WIDTH * n]
            if int.from_bytes(leaf[:8], "big") >= ts_ms:
                hi = mid
            else:
                lo = mid + 1
        return lo
