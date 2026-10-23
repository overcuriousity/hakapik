"""HTTP client for classic RFC 6962 Certificate Transparency logs."""

import base64

import httpx

from hakapik.ct._retry import retry_get
from hakapik.ct.loglist import LogInfo


def _leaf_timestamp_ms(leaf_input: bytes) -> int:
    # version (1 byte), leaf_type (1 byte), then 8-byte big-endian timestamp
    return int.from_bytes(leaf_input[2:10], "big")


class Rfc6962Log:
    def __init__(self, info: LogInfo, client: httpx.AsyncClient):
        self.info = info
        self._client = client

    async def tree_size(self) -> int:
        resp = await retry_get(self._client, f"{self.info.url}ct/v1/get-sth")
        return int(resp.json()["tree_size"])

    async def entries(self, start: int, end: int) -> list[tuple[int, bytes, bytes]]:
        """Fetch entries start..end inclusive; the log may return fewer."""
        resp = await retry_get(
            self._client,
            f"{self.info.url}ct/v1/get-entries",
            params={"start": start, "end": end},
        )
        return [
            (
                start + i,
                base64.b64decode(e["leaf_input"]),
                base64.b64decode(e["extra_data"]),
            )
            for i, e in enumerate(resp.json()["entries"])
        ]

    async def index_at(self, ts_ms: int) -> int:
        """First index whose timestamp is >= ts_ms, or tree_size if none."""
        lo, hi = 0, await self.tree_size()
        while lo < hi:
            mid = (lo + hi) // 2
            got = await self.entries(mid, mid)
            if not got:
                raise RuntimeError(f"log returned no entry for index {mid}")
            if _leaf_timestamp_ms(got[0][1]) >= ts_ms:
                hi = mid
            else:
                lo = mid + 1
        return lo
