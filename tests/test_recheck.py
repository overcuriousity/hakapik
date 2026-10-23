from datetime import datetime, timezone
from pathlib import Path

import pytest

from hakapik.blobstore import BlobStore
from hakapik.db import CandidateRow, add_candidates, read_stat
from hakapik.firstseen import FirstSeenIndex
from hakapik.ingest import StatCounter, process_batch
from hakapik.names import normalize
from hakapik.suppress import Suppressor
from test_ingest import EXPECTED_FQDN, INFO, LEAF_X509, FakeSource

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


async def _fetched(conn, days_ago):
    """A finished job + attempt for EXPECTED_FQDN, days_ago days in the past."""
    await add_candidates(
        conn, [CandidateRow(EXPECTED_FQDN, REGISTRABLE, "oldlog", 0, b"old", 1)]
    )
    cur = await conn.execute("UPDATE fetch_job SET state = 'done' RETURNING id")
    jid = (await cur.fetchone())[0]
    await conn.execute("INSERT INTO node (node_id, public_key) VALUES ('n', 'k')")
    await conn.execute("INSERT INTO blob (sha256, size, media_type) VALUES ('s', 1, 'x')")
    await conn.execute(
        """INSERT INTO attempt (job_id, step, node_id, started_at, finished_at, outcome, envelope_sha256)
           VALUES (%s, 0, 'n', now() - make_interval(days => %s),
                   now() - make_interval(days => %s), 'live', 's')""",
        (jid, days_ago, days_ago),
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
