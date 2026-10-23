import os
from datetime import date

import pytest

from hakapik.db import (
    CandidateRow,
    add_candidates,
    add_raw_batch,
    bump_stat,
    get_cursor,
    read_stat,
    set_cursor,
)

pytestmark = pytest.mark.skipif(
    not os.getenv("HAKAPIK_TEST_DB"), reason="needs postgres"
)


async def _count(conn, table):
    cur = await conn.execute(f"SELECT count(*) FROM {table}")
    return (await cur.fetchone())[0]


async def test_cursor_and_stat_roundtrip(conn):
    await set_cursor(conn, "L", 10, False)
    assert await get_cursor(conn, "L") == (10, False)
    await bump_stat(conn, "L", date(2026, 10, 23), entries=5)
    await bump_stat(conn, "L", date(2026, 10, 23), entries=2)
    assert (await read_stat(conn, "L", date(2026, 10, 23)))["entries"] == 7


async def test_get_cursor_absent(conn):
    assert await get_cursor(conn, "nope") == (0, False)


async def test_set_cursor_upserts(conn):
    await set_cursor(conn, "L", 1, False)
    await set_cursor(conn, "L", 99, True)
    assert await get_cursor(conn, "L") == (99, True)
    assert await _count(conn, "log_cursor") == 1


async def test_add_candidates(conn):
    rows = [
        CandidateRow("a.example.com", "example.com", "L", i, b"\x01\x02", 1000 + i)
        for i in range(3)
    ]
    await add_candidates(conn, rows)
    assert await _count(conn, "candidate") == 3
    cur = await conn.execute("SELECT cert_key FROM candidate LIMIT 1")
    assert bytes((await cur.fetchone())[0]) == b"\x01\x02"


async def test_add_raw_batch(conn):
    await add_raw_batch(conn, "L", 0, 255, "ab" * 32, 256, 4096)
    assert await _count(conn, "raw_batch") == 1
    cur = await conn.execute("SELECT entries, bytes FROM raw_batch")
    assert await cur.fetchone() == (256, 4096)


async def test_read_stat_absent_is_zeros(conn):
    stat = await read_stat(conn, "L", date(2026, 10, 23))
    assert stat and all(v == 0 for v in stat.values())


async def test_bump_stat_unknown_column(conn):
    with pytest.raises(ValueError):
        await bump_stat(conn, "L", date(2026, 10, 23), bogus=1)
