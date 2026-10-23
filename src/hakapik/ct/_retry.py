"""Shared GET helper with exponential backoff for CT log clients."""

import asyncio

import httpx

_sleep = asyncio.sleep  # monkeypatched in tests

BASE_DELAY = 1.0
MAX_DELAY = 60.0
RETRY_AFTER_CAP = 600.0


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After")
    if value is not None and value.strip().isdigit():
        return min(float(value), RETRY_AFTER_CAP)
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
    overrides it (capped at 600 s). Only 5xx and transport errors count
    toward ``max_attempts``; 429 (rate limiting) is retried indefinitely,
    since the log is healthy and asking us to slow down. Once the attempts
    are used up the last error is raised; other 4xx are raised at once.
    """
    delay = BASE_DELAY
    failures = 0
    while True:
        wait = delay
        try:
            response = await client.get(url, params=params)
        except httpx.TransportError:
            failures += 1
            if failures >= max_attempts:
                raise
        else:
            status = response.status_code
            if status != 429 and status < 500:
                response.raise_for_status()
                return response
            hinted = _retry_after(response)
            if hinted is not None:
                wait = hinted
            if status >= 500:
                failures += 1
                if failures >= max_attempts:
                    response.raise_for_status()
        await _sleep(wait)
        delay = min(delay * 2, MAX_DELAY)
