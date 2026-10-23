import httpx
import pytest

from hakapik.ct import _retry
from hakapik.ct._retry import retry_get

URL = "https://ct.example.test/x"


@pytest.fixture(autouse=True)
def delays(monkeypatch):
    out: list[float] = []

    async def fake_sleep(d):
        out.append(d)

    monkeypatch.setattr(_retry, "_sleep", fake_sleep)
    return out


async def test_backoff_doubles_and_caps(respx_mock, delays):
    respx_mock.get(URL).mock(side_effect=[httpx.Response(503)] * 8)
    async with httpx.AsyncClient() as c:
        with pytest.raises(httpx.HTTPStatusError):
            await retry_get(c, URL, max_attempts=8)
    assert delays == [1, 2, 4, 8, 16, 32, 60]


async def test_retry_after_honoured_and_capped(respx_mock, delays):
    respx_mock.get(URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(429, headers={"Retry-After": "500"}),
            httpx.Response(429, headers={"Retry-After": "900"}),
            httpx.Response(200),
        ]
    )
    async with httpx.AsyncClient() as c:
        r = await retry_get(c, URL)
    assert r.status_code == 200
    assert delays == [7, 500, 600]


async def test_429_does_not_count_toward_max_attempts(respx_mock, delays):
    route = respx_mock.get(URL).mock(
        side_effect=[httpx.Response(429)] * 10 + [httpx.Response(200)]
    )
    async with httpx.AsyncClient() as c:
        r = await retry_get(c, URL, max_attempts=2)
    assert r.status_code == 200 and route.call_count == 11


async def test_5xx_still_bounded_between_429s(respx_mock, delays):
    respx_mock.get(URL).mock(
        side_effect=[httpx.Response(429), httpx.Response(503), httpx.Response(429),
                     httpx.Response(503)]
    )
    async with httpx.AsyncClient() as c:
        with pytest.raises(httpx.HTTPStatusError) as ei:
            await retry_get(c, URL, max_attempts=2)
    assert ei.value.response.status_code == 503 and len(delays) == 3


async def test_transport_error_retried_then_raised(respx_mock, delays):
    route = respx_mock.get(URL).mock(side_effect=httpx.ConnectError("boom"))
    async with httpx.AsyncClient() as c:
        with pytest.raises(httpx.ConnectError):
            await retry_get(c, URL, max_attempts=3)
    assert route.call_count == 3 and len(delays) == 2


async def test_4xx_not_retried(respx_mock, delays):
    route = respx_mock.get(URL).mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as c:
        with pytest.raises(httpx.HTTPStatusError):
            await retry_get(c, URL)
    assert route.call_count == 1 and delays == []
