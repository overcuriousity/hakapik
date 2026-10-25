from datetime import datetime, timezone
from pathlib import Path

import pytest

from hakapik.blobstore import BlobStore
from hakapik.config import Config
from hakapik.db import CandidateRow, add_candidates, read_stat, set_cursor
from hakapik.firstseen import FirstSeenIndex
from hakapik.ingest import StatCounter, process_batch, tail_log_once
from hakapik.jobs import enqueue_manual
from hakapik.names import normalize
from hakapik.suppress import Suppressor
from test_ingest import EXPECTED_FQDN, INFO, LEAF_X509, FakeSource, _synth, synth  # noqa: F401

REGISTRABLE = "myvolumio.org"


@pytest.fixture
def fake():
    return FakeSource([LEAF_X509])


@pytest.fixture
def ix(tmp_path):
    with FirstSeenIndex(tmp_path / "firstseen") as index:
        index.first_seen(EXPECTED_FQDN, 1, "oldlog", 0)
        yield index


@pytest.fixture
def bs(tmp_path):
    return BlobStore(tmp_path / "blobs")


async def _fetched(conn, days_ago, fqdn=EXPECTED_FQDN, registrable=REGISTRABLE, hours=0):
    """A finished job + attempt for ``fqdn``, finished days_ago days (+ hours) ago."""
    await add_candidates(
        conn, [CandidateRow(fqdn, registrable, "oldlog", 0, b"old", 1)]
    )
    cur = await conn.execute(
        "UPDATE fetch_job SET state = 'done' WHERE fqdn = %s RETURNING id", (fqdn,)
    )
    jid = (await cur.fetchone())[0]
    await conn.execute(
        "INSERT INTO node (node_id, public_key) VALUES ('n', 'k') ON CONFLICT DO NOTHING"
    )
    await conn.execute(
        "INSERT INTO blob (sha256, size, media_type) VALUES ('s', 1, 'x') ON CONFLICT DO NOTHING"
    )
    await conn.execute(
        """INSERT INTO attempt (job_id, step, node_id, started_at, finished_at, outcome, envelope_sha256)
           VALUES (%s, 0, 'n', now() - make_interval(days => %s, hours => %s),
                   now() - make_interval(days => %s, hours => %s), 'live', 's')""",
        (jid, days_ago, hours, days_ago, hours),
    )
    await conn.commit()


async def _run(fake, ix, bs, conn, sup=None):
    stats = StatCounter()
    sup = sup or Suppressor(frozenset(), frozenset())
    await process_batch(fake, 0, 0, ix=ix, sup=sup, bs=bs, conn=conn, stats=stats)
    cur = await conn.execute(
        "SELECT fqdn, reason, log_id, log_index FROM candidate WHERE reason = 'recheck'"
    )
    return stats, await cur.fetchall()


async def test_old_fetch_renewal_becomes_recheck_candidate(fake, ix, bs, conn):
    await _fetched(conn, 40)
    stats, rows = await _run(fake, ix, bs, conn)
    assert rows == [(EXPECTED_FQDN, "recheck", INFO.log_id, 0)]
    assert stats.candidates_recheck == 1
    assert stats.candidates == 0  # first-seen count stays apart
    day = datetime.now(timezone.utc).date()
    assert (await read_stat(conn, INFO.log_id, day))["candidates_recheck"] == 1


async def test_recent_fetch_is_not_rechecked(fake, ix, bs, conn):
    await _fetched(conn, 5)
    stats, rows = await _run(fake, ix, bs, conn)
    assert rows == [] and stats.candidates_recheck == 0


async def test_never_fetched_is_not_rechecked(fake, ix, bs, conn):
    stats, rows = await _run(fake, ix, bs, conn)
    assert rows == [] and stats.candidates_recheck == 0


async def test_top_listed_registrable_is_not_rechecked(fake, ix, bs, conn):
    await _fetched(conn, 40)
    sup = Suppressor(frozenset({REGISTRABLE}), frozenset())
    # The name itself is not suppressed; only its registrable domain is top-listed.
    assert sup.top_listed(REGISTRABLE) and sup.reason(normalize(EXPECTED_FQDN)) is None
    stats, rows = await _run(fake, ix, bs, conn, sup)
    assert rows == [] and stats.candidates_recheck == 0


async def test_suppressed_indexed_name_is_not_rechecked(fake, ix, bs, conn):
    await _fetched(conn, 40)
    sup = Suppressor(frozenset(), frozenset({EXPECTED_FQDN}))
    stats, rows = await _run(fake, ix, bs, conn, sup)
    assert rows == [] and stats.candidates_recheck == 0


async def test_indexed_wildcard_is_not_rechecked_as_its_apex(synth, tmp_path, bs, conn):
    # The wildcard shares fqdn "a.com" with the apex, which was fetched long ago.
    await _fetched(conn, 40, "a.com", "a.com")
    with FirstSeenIndex(tmp_path / "fs2") as ix:
        ix.first_seen("*.a.com", 1, "oldlog", 0)
        stats, rows = await _run(FakeSource([_synth("1", "*.a.com")]), ix, bs, conn)
    assert rows == [] and stats.candidates_recheck == 0


async def test_name_in_two_certs_of_one_batch_is_rechecked_once(synth, tmp_path, bs, conn):
    await _fetched(conn, 40, "a.com", "a.com")
    src = FakeSource([_synth("1", "a.com"), _synth("2", "a.com", "www.a.com")])
    with FirstSeenIndex(tmp_path / "fs2") as ix:
        ix.first_seen("a.com", 1, "oldlog", 0)
        stats = StatCounter()
        sup = Suppressor(frozenset(), frozenset())
        await process_batch(src, 0, 1, ix=ix, sup=sup, bs=bs, conn=conn, stats=stats)
    cur = await conn.execute("SELECT fqdn, log_index FROM candidate WHERE reason = 'recheck'")
    assert await cur.fetchall() == [("a.com", 0)]
    assert stats.candidates_recheck == 1 and stats.candidates == 1  # www.a.com is new


@pytest.mark.parametrize("hours, rechecked", [(-1, False), (1, True)])
async def test_recheck_boundary(fake, ix, bs, conn, hours, rechecked):
    # recheck_days is 30: an hour inside the window is not re-checked, an hour
    # past it is.
    await _fetched(conn, 30, hours=hours)
    stats, rows = await _run(fake, ix, bs, conn)
    assert stats.candidates_recheck == int(rechecked) and len(rows) == int(rechecked)


async def test_open_job_blocks_a_second_recheck_candidate(fake, ix, bs, conn):
    await _fetched(conn, 40)
    # Another log's batch already re-checked the name: its job is still open.
    await enqueue_manual(conn, [EXPECTED_FQDN])
    await conn.commit()
    stats, rows = await _run(fake, ix, bs, conn)
    assert rows == [] and stats.candidates_recheck == 0


async def test_tail_passes_cfg_recheck_days(fake, ix, bs, conn, tmp_path):
    await _fetched(conn, 20)  # inside the default 30 days, past 10
    await set_cursor(conn, INFO.log_id, 0)
    await conn.commit()
    sup = Suppressor(frozenset(), frozenset())
    cfg = Config(data_dir=tmp_path, database_url="unused", batch_size=1, recheck_days=10)
    assert await tail_log_once(fake, cfg, ix, sup, bs, conn) == 1
    cur = await conn.execute("SELECT fqdn FROM candidate WHERE reason = 'recheck'")
    assert await cur.fetchall() == [(EXPECTED_FQDN,)]
