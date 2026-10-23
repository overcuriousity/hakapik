from pathlib import Path

import httpx
import pytest

from hakapik.ct.leaf import ParsedLeaf, parse_tile_leaf
from hakapik.ct.loglist import LogInfo
from hakapik.ct.rfc6962 import Rfc6962Log
from hakapik.ct.source import base_url, make_source
from hakapik.ct.static_ct import StaticCtLog, parse_checkpoint, tile_path

MON = "https://mon.example.test/tiled/"
FIX = Path(__file__).parent / "fixtures" / "tile_data_small.bin"


def _info(kind="tiled", url="https://sub.example.test/tiled", mon=MON):
    return LogInfo("id", "d", kind, url, mon, "usable", "op")


def _leaf_slices() -> list[bytes]:
    buf = memoryview(FIX.read_bytes())
    out, off = [], 0
    while off < len(buf):
        rec, nxt = parse_tile_leaf(buf, off)
        assert isinstance(rec, ParsedLeaf)
        out.append(bytes(buf[off:nxt]))
        off = nxt
    return out


def make_tile(width: int, base: int = 0) -> tuple[bytes, list[bytes]]:
    pool = _leaf_slices()
    leaves = [pool[(base + i) % len(pool)] for i in range(width)]
    return b"".join(leaves), leaves


def checkpoint(size: int) -> str:
    return f"example.org/log\n{size}\nAAAA\n\n— example.org/log sig\n"


@pytest.fixture
def tlog():
    return StaticCtLog(_info(), httpx.AsyncClient())


def test_parse_checkpoint():
    size, root = parse_checkpoint(
        "example.org/log\n12345\nAAECAw==\n\n— example.org/log sigb64\n"
    )
    assert size == 12345
    assert root == b"\x00\x01\x02\x03"


def test_tile_path_encodes_three_digit_groups():
    assert tile_path(1234567, None) == "tile/data/x001/x234/567"
    assert tile_path(5, 200) == "tile/data/005.p/200"
    assert tile_path(0, None) == "tile/data/000"


def test_base_url_single_trailing_slash():
    assert base_url("https://a/b") == "https://a/b/"
    assert base_url("https://a/b/") == "https://a/b/"
    assert base_url("https://a/b//") == "https://a/b/"


async def test_tree_size(respx_mock, tlog):
    respx_mock.get(MON + "checkpoint").respond(text=checkpoint(300))
    assert await tlog.tree_size() == 300


async def test_entries_spanning_two_tiles(respx_mock, tlog):
    t0, l0 = make_tile(256)
    t1, l1 = make_tile(256, 256)
    respx_mock.get(MON + "checkpoint").respond(text=checkpoint(1000))
    respx_mock.get(MON + "tile/data/000").respond(content=t0)
    respx_mock.get(MON + "tile/data/001").respond(content=t1)
    out = await tlog.entries(254, 258)
    assert [i for i, *_ in out] == [254, 255, 256, 257, 258]
    assert [b for _, b, _ in out] == l0[254:] + l1[:3]
    assert all(x == b"" for *_, x in out)
    rec, nxt = parse_tile_leaf(memoryview(out[0][1]), 0)
    assert isinstance(rec, ParsedLeaf) and nxt == len(out[0][1])


async def test_entries_partial_last_tile(respx_mock, tlog):
    t, leaves = make_tile(44)
    respx_mock.get(MON + "checkpoint").respond(text=checkpoint(300))
    route = respx_mock.get(MON + "tile/data/001.p/44").respond(content=t)
    out = await tlog.entries(290, 299)
    assert route.called
    assert [i for i, *_ in out] == list(range(290, 300))
    assert [b for _, b, _ in out] == leaves[34:44]


async def test_entries_clamps_beyond_tree_size(respx_mock, tlog):
    t, leaves = make_tile(44)
    respx_mock.get(MON + "checkpoint").respond(text=checkpoint(300))
    respx_mock.get(MON + "tile/data/001.p/44").respond(content=t)
    out = await tlog.entries(298, 400)
    assert [i for i, *_ in out] == [298, 299]


async def test_truncated_tile_raises(respx_mock, tlog):
    t, _ = make_tile(256)
    respx_mock.get(MON + "checkpoint").respond(text=checkpoint(256))
    respx_mock.get(MON + "tile/data/000").respond(content=t[:-5])
    with pytest.raises(RuntimeError, match="cannot delimit"):
        await tlog.entries(0, 255)


def test_make_source_dispatch():
    c = httpx.AsyncClient()
    assert isinstance(make_source(_info("tiled"), c), StaticCtLog)
    assert isinstance(make_source(_info("rfc6962", mon=None), c), Rfc6962Log)


async def test_undecodable_last_leaf_does_not_block_tile(respx_mock, tlog):
    t, leaves = make_tile(3)
    bad = bytearray(leaves[2])
    bad[40:56] = b"\xff" * 16
    data = leaves[0] + leaves[1] + bytes(bad)
    respx_mock.get(MON + "checkpoint").respond(text=checkpoint(3))
    respx_mock.get(MON + "tile/data/000.p/3").respond(content=data)
    out = await tlog.entries(0, 2)
    assert [i for i, *_ in out] == [0, 1, 2]
    assert out[2][1] == bytes(bad)
