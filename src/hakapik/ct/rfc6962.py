"""HTTP client for classic RFC 6962 Certificate Transparency logs."""

import base64

import httpx

from hakapik.ct._retry import retry_get
from hakapik.ct.loglist import LogInfo
from hakapik.ct.source import base_url


class Rfc6962Log:
    def __init__(self, info: LogInfo, client: httpx.AsyncClient):
        self.info = info
        self._client = client
        self._base = base_url(info.url)

    async def tree_size(self) -> int:
        resp = await retry_get(self._client, f"{self._base}ct/v1/get-sth")
        return int(resp.json()["tree_size"])

    async def entries(self, start: int, end: int) -> list[tuple[int, bytes, bytes]]:
        """Fetch entries start..end inclusive; the log may return fewer."""
        resp = await retry_get(
            self._client,
            f"{self._base}ct/v1/get-entries",
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
