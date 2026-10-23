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
    read_stats,
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
    await bump_stat(conn, "L", date(2026, 10, 23), "live", entries=5)
    await bump_stat(conn, "L", date(2026, 10, 23), "live", entries=2)
    assert (await read_stat(conn, "L", date(2026, 10, 23), "live"))["entries"] == 7


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
        await bump_stat(conn, "L", date(2026, 10, 23), "live", bogus=1)


async def test_stat_rows_are_per_mode(conn):
    d = date(2026, 10, 23)
    await bump_stat(conn, "L", d, "bootstrap", entries=10, supp_tranco=1)
    await bump_stat(conn, "L", d, "live", entries=3, supp_wildcard=2)
    assert (await read_stat(conn, "L", d, "bootstrap"))["entries"] == 10
    assert (await read_stat(conn, "L", d, "live"))["supp_wildcard"] == 2
    both = await read_stat(conn, "L", d)
    assert (both["entries"], both["supp_tranco"], both["supp_wildcard"]) == (13, 1, 2)
    rows = await read_stats(conn, d)
    assert [(r["log_id"], r["mode"]) for r in rows] == [("L", "bootstrap"), ("L", "live")]


async def test_migrate_creates_indexes(conn):
    cur = await conn.execute(
        "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'"
    )
    names = {r[0] for r in await cur.fetchall()}
    assert {
        "candidate_log_index", "raw_batch_created_at", "raw_batch_blob_sha256"
    } <= names
