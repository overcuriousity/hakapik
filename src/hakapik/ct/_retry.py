"""Shared GET helper with exponential backoff for CT log clients."""

import asyncio

import httpx

_sleep = asyncio.sleep  # monkeypatched in tests

BASE_DELAY = 1.0
MAX_DELAY = 60.0


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After")
    if value is not None and value.strip().isdigit():
        return min(float(value), MAX_DELAY)
    return None


async def retry_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict | None = None,
    max_attempts: int = 8,
) -> httpx.Response:
    """GET with retries on 429, 5xx and transport errors.

    Backoff doubles from 1 s up to 60 s; an integer Retry-After header
    overrides it (also capped at 60 s). The last error is re-raised.
    """
    delay = BASE_DELAY
    for attempt in range(1, max_attempts + 1):
        wait = delay
        try:
            response = await client.get(url, params=params)
            if response.status_code != 429 and response.status_code < 500:
                response.raise_for_status()
                return response
            hinted = _retry_after(response)
            if hinted is not None:
                wait = hinted
            response.raise_for_status()
        except httpx.TransportError:
            if attempt == max_attempts:
                raise
        except httpx.HTTPStatusError:
            if attempt == max_attempts or not (
                response.status_code == 429 or response.status_code >= 500
            ):
                raise
        await _sleep(wait)
        delay = min(delay * 2, MAX_DELAY)
    raise AssertionError("unreachable")  # pragma: no cover
