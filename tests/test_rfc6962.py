import base64

import httpx
import pytest

from hakapik.ct import _retry
from hakapik.ct.loglist import LogInfo
from hakapik.ct.rfc6962 import Rfc6962Log

BASE = "https://ct.example.test/logs/argon/"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


TWO_ENTRIES = {
    "entries": [
        {"leaf_input": b64(b"leaf-a"), "extra_data": b64(b"extra-a")},
        {"leaf_input": b64(b"leaf-b"), "extra_data": b64(b"extra-b")},
    ]
}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    delays: list[float] = []

    async def fake_sleep(delay):
        delays.append(delay)

    monkeypatch.setattr(_retry, "_sleep", fake_sleep)
    return delays


@pytest.fixture
async def log():
    info = LogInfo(
        log_id="id",
        description="Argon",
        kind="rfc6962",
        url=BASE,
        monitoring_url=None,
        state="usable",
        operator="Op",
    )
    async with httpx.AsyncClient() as client:
        yield Rfc6962Log(info, client)


async def test_info_exposed(log):
    assert log.info.url == BASE


async def test_tree_size(respx_mock, log):
    respx_mock.get(BASE + "ct/v1/get-sth").mock(
        return_value=httpx.Response(
            200,
            json={
                "tree_size": 1234,
                "timestamp": 1,
                "sha256_root_hash": "",
                "tree_head_signature": "",
            },
        )
    )
    assert await log.tree_size() == 1234


async def test_entries_decodes_base64(respx_mock, log):
    route = respx_mock.get(url__regex=r".*get-entries.*").mock(
        return_value=httpx.Response(200, json=TWO_ENTRIES)
    )
    out = await log.entries(5, 6)
    assert out == [(5, b"leaf-a", b"extra-a"), (6, b"leaf-b", b"extra-b")]
    assert route.calls[0].request.url.params["start"] == "5"
    assert route.calls[0].request.url.params["end"] == "6"


async def test_entries_may_return_fewer(respx_mock, log):
    respx_mock.get(url__regex=r".*get-entries.*").mock(
        return_value=httpx.Response(200, json={"entries": TWO_ENTRIES["entries"][:1]})
    )
    assert await log.entries(10, 19) == [(10, b"leaf-a", b"extra-a")]


async def test_get_entries_retries_on_429(respx_mock, log, no_sleep):
    route = respx_mock.get(url__regex=r".*get-entries.*").mock(
        side_effect=[httpx.Response(429), httpx.Response(200, json=TWO_ENTRIES)]
    )
    out = await log.entries(0, 1)
    assert len(out) == 2 and route.call_count == 2
    assert no_sleep == [1]


async def test_entries_trims_overlong_response(respx_mock, log):
    respx_mock.get(url__regex=r".*get-entries.*").mock(
        return_value=httpx.Response(200, json=TWO_ENTRIES)
    )
    assert await log.entries(7, 7) == [(7, b"leaf-a", b"extra-a")]


async def test_entries_empty_log(respx_mock, log):
    respx_mock.get(url__regex=r".*get-entries.*").mock(
        return_value=httpx.Response(200, json={"entries": []})
    )
    assert await log.entries(0, 9) == []


async def test_entries_exhausted_5xx_raises(respx_mock, log, no_sleep):
    route = respx_mock.get(url__regex=r".*get-entries.*").mock(
        return_value=httpx.Response(503)
    )
    with pytest.raises(httpx.HTTPStatusError):
        await log.entries(0, 1)
    assert route.call_count == 8 and len(no_sleep) == 7
