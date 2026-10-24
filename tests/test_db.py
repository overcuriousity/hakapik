import asyncio
import os
from datetime import date

import pytest

from hakapik.db import (
    CandidateRow,
    add_candidates,
    add_raw_batch,
    connect,
    bump_stat,
    get_cursor,
    migrate,
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
    await set_cursor(conn, "L", 10)
    assert await get_cursor(conn, "L") == 10
    await bump_stat(conn, "L", date(2026, 10, 23), entries=5)
    await bump_stat(conn, "L", date(2026, 10, 23), entries=2)
    assert (await read_stat(conn, "L", date(2026, 10, 23)))["entries"] == 7


async def test_get_cursor_absent(conn):
    assert await get_cursor(conn, "nope") is None


async def test_set_cursor_upserts(conn):
    await set_cursor(conn, "L", 1)
    await set_cursor(conn, "L", 99)
    assert await get_cursor(conn, "L") == 99
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


async def test_stat_rows_are_per_log_and_day(conn):
    d = date(2026, 10, 23)
    await bump_stat(conn, "L", d, entries=10, supp_tranco=1)
    await bump_stat(conn, "L", d, entries=3, supp_wildcard=2)
    await bump_stat(conn, "M", d, entries=1)
    stat = await read_stat(conn, "L", d)
    assert (stat["entries"], stat["supp_tranco"], stat["supp_wildcard"]) == (13, 1, 2)
    rows = await read_stats(conn, d)
    assert [(r["log_id"], r["entries"]) for r in rows] == [("L", 13), ("M", 1)]
    assert "mode" not in rows[0]


async def test_migrate_creates_indexes(conn):
    cur = await conn.execute(
        "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'"
    )
    names = {r[0] for r in await cur.fetchall()}
    assert {
        "candidate_log_index", "raw_batch_created_at", "raw_batch_blob_sha256"
    } <= names


STAGE_ONE_CANDIDATE_DDL = """CREATE TABLE candidate (
    id bigserial PRIMARY KEY,
    fqdn text NOT NULL,
    registrable text NOT NULL,
    log_id text NOT NULL,
    log_index bigint NOT NULL,
    cert_key bytea NOT NULL,
    first_seen_ms bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
)"""


async def test_new_tables_exist(conn):
    for t in ("fetch_job", "attempt", "dns_answer", "artifact", "blob", "manifest", "node"):
        cur = await conn.execute("SELECT to_regclass(%s)", (t,))
        assert (await cur.fetchone())[0] is not None


async def test_migrate_upgrades_old_candidate_table(conn):
    # a stage-one candidate table (NOT NULL log columns, no reason) is upgraded in place
    await conn.execute("DROP TABLE candidate CASCADE")
    await conn.execute(STAGE_ONE_CANDIDATE_DDL)
    await migrate(conn)
    await conn.execute(
        "INSERT INTO candidate (fqdn, registrable, reason) "
        "VALUES ('a.example.com','example.com','manual')"
    )


async def test_migrate_is_idempotent(conn):
    await migrate(conn)
    await migrate(conn)


async def test_second_migrate_takes_no_exclusive_lock(conn):
    # a reader holding ACCESS SHARE blocks any ALTER TABLE; a second migrate must not need one
    other = await connect(os.environ["HAKAPIK_TEST_DB"])
    try:
        await other.execute("LOCK TABLE candidate, ingest_stat IN ACCESS SHARE MODE")
        await conn.execute("SET lock_timeout = '1s'")
        await migrate(conn)
    finally:
        await other.close()


async def test_concurrent_overlapping_candidates_do_not_deadlock(conn):
    # The same certificate reaches several logs, so concurrent log tasks insert
    # the same names; fetch_job's unique open-fqdn index makes them wait on each
    # other, which deadlocks unless every batch inserts in one global order.
    url = os.environ["HAKAPIK_TEST_DB"]

    async def batch(names):
        c = await connect(url)
        try:
            rows = [CandidateRow(n, "example.com", "L", i, b"k", 0) for i, n in enumerate(names)]
            await add_candidates(c, rows)
            await c.commit()
        finally:
            await c.close()

    for r in range(3):
        names = [f"h{r}-{i}.example.com" for i in range(2000)]
        await asyncio.gather(batch(names), batch(names[::-1]))
    assert await _count(conn, "fetch_job") == 6000
