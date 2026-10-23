import json
from pathlib import Path

import httpx
import pytest

from hakapik.ct.loglist import LogInfo, fetch_log_lists, parse_log_list

FIXTURES = Path(__file__).parent / "fixtures"
V3_URL = "https://example.test/v3/log_list.json"
APPLE_URL = "https://example.test/apple/current_log_list.json"
ALLOWED = {"usable", "qualified", "readonly"}


@pytest.fixture
def v3_fixture():
    return json.loads((FIXTURES / "log_list_v3_small.json").read_text())


@pytest.fixture
def apple_fixture():
    return json.loads((FIXTURES / "apple_log_list_small.json").read_text())


def test_parse_marks_tiled_logs(v3_fixture):
    logs = parse_log_list(v3_fixture)
    tiled = [l for l in logs if l.kind == "tiled"]
    assert tiled and all(l.monitoring_url for l in tiled)
    assert all(l.url.endswith("/") and l.url != l.monitoring_url for l in tiled)
    classic = [l for l in logs if l.kind == "rfc6962"]
    assert classic and all(l.monitoring_url is None for l in classic)


def test_parse_drops_retired_and_pending(v3_fixture):
    logs = parse_log_list(v3_fixture)
    assert all(l.state in ALLOWED for l in logs)
    assert {l.state for l in logs} == {"usable", "qualified"}


def test_parse_maps_fields(v3_fixture):
    by_op = {l.operator for l in parse_log_list(v3_fixture)}
    assert by_op == {"Google", "Let's Encrypt"}
    info = parse_log_list(v3_fixture)[0]
    assert isinstance(info, LogInfo)
    assert info.log_id and info.description and info.url


async def test_fetch_merges_and_dedups(respx_mock, v3_fixture, apple_fixture):
    respx_mock.get(V3_URL).mock(return_value=httpx.Response(200, json=v3_fixture))
    respx_mock.get(APPLE_URL).mock(return_value=httpx.Response(200, json=apple_fixture))
    async with httpx.AsyncClient() as client:
        logs = await fetch_log_lists([V3_URL, APPLE_URL], client)
    ids = [l.log_id for l in logs]
    assert len(ids) == len(set(ids))
    assert all(l.state in ALLOWED for l in logs)
    v3_ids = {l.log_id for l in parse_log_list(v3_fixture)}
    apple_ids = {l.log_id for l in parse_log_list(apple_fixture)}
    assert v3_ids & apple_ids
    assert set(ids) == v3_ids | apple_ids
    assert len(ids) < len(v3_ids) + len(apple_ids)


def test_parse_drops_pending_and_rejected():
    def log(log_id, state):
        return {"log_id": log_id, "description": log_id, "url": "https://x/", "state": state}

    data = {"operators": [{"name": "Op", "logs": [
        log("a", {"pending": {"timestamp": "t"}}),
        log("b", {"rejected": {"timestamp": "t"}}),
        log("c", {"readonly": {"timestamp": "t"}}),
    ]}]}
    assert [l.log_id for l in parse_log_list(data)] == ["c"]
