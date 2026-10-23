import asyncio
import dataclasses
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

import hakapik.ingest as ingest
from hakapik.blobstore import BlobStore
from hakapik.config import Config
from hakapik.ct.leaf import parse_rfc6962_leaf
from hakapik.ct.loglist import LogInfo
from hakapik.db import connect as real_connect
from hakapik.db import get_cursor, read_stat, set_cursor
from hakapik.firstseen import FirstSeenIndex
from hakapik.ingest import (
    StatCounter,
    bootstrap_log,
    pack_entries,
    process_batch,
    tail_log,
    tail_log_once,
    unpack_entries,
)
from hakapik.suppress import Suppressor

FIX = Path(__file__).parent / "fixtures"
LEAF_X509 = (FIX / "leaf_x509.bin").read_bytes()
LEAF_PRECERT = (FIX / "leaf_precert.bin").read_bytes()
GARBAGE = b"\x00\x00garbage"

# From tests/test_leaf.py (EXPECTED_SANS_X509 / EXPECTED_SANS_PRECERT).
EXPECTED_FQDN = "5432fa62e219259ae1093a2a226565b6ee8a.eu2.myvolumio.org"
EXPECTED_NEW_FQDNS = {
    EXPECTED_FQDN,
    "9950eab53001792788541807.osu.prod.canaries.quickbeam.acm.aws.dev",
    "san0.9950eab53001792788541807.osu.prod.canaries.quickbeam.acm.aws.dev",
}

INFO = LogInfo(
    log_id="fakelogid",
    description="Fake Log",
    kind="rfc6962",
    url="https://fake.invalid/",
    monitoring_url=None,
    state="usable",
    operator="Fake",
)


class FakeSource:
    """In-memory LogSource; entries are (index, leaf, extra) with index == position."""

    def __init__(self, leaves: list[bytes], info: LogInfo = INFO):
        self.info = info
        self._entries = [(i, leaf, b"extra%d" % i) for i, leaf in enumerate(leaves)]
        self.calls: list[tuple[int, int]] = []

    async def tree_size(self) -> int:
        return len(self._entries)

    async def entries(self, start: int, end: int) -> list[tuple[int, bytes, bytes]]:
        self.calls.append((start, end))
        return self._entries[start : end + 1]

    async def index_at(self, ts_ms: int) -> int:
        for i, leaf, _ in self._entries:
            p = parse_rfc6962_leaf(leaf)
            if getattr(p, "timestamp_ms", None) is not None and p.timestamp_ms >= ts_ms:
                return i
        return len(self._entries)


class FailingBlobStore(BlobStore):
    def put(self, data: bytes, media_type: str) -> str:
        raise OSError("disk full")


@pytest.fixture
def fake():
    # Indices 2 and 3 repeat the certs of 0 and 1 at other log indices.
    return FakeSource([LEAF_X509, LEAF_PRECERT, LEAF_X509, LEAF_PRECERT])


@pytest.fixture
def ix(tmp_path):
    with FirstSeenIndex(tmp_path / "firstseen") as index:
        yield index


@pytest.fixture
def sup():
    return Suppressor(frozenset(), frozenset())


@pytest.fixture
def bs(tmp_path):
    return BlobStore(tmp_path / "blobs")


@pytest.fixture
def cfg(tmp_path):
    return Config(data_dir=tmp_path, database_url="unused", batch_size=2)


async def count(conn, table: str) -> int:
    cur = await conn.execute(f"SELECT count(*) FROM {table}")
    return (await cur.fetchone())[0]


async def bootstrapped(conn, log_id=INFO.log_id, next_index=0):
    await set_cursor(conn, log_id, next_index, True)
    await conn.commit()


def today():
    return datetime.now(timezone.utc).date()


def test_pack_roundtrip():
    entries = [(0, b"leaf0", b""), (2**40, b"", b"extra"), (7, b"\x00" * 300, b"\x01")]
    assert unpack_entries(pack_entries(entries)) == entries
    assert unpack_entries(pack_entries([])) == []


async def test_bootstrap_writes_index_only(fake, ix, sup, bs, conn):
    await process_batch(fake, 0, 1, mode="bootstrap", ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    assert ix.get(EXPECTED_FQDN) is not None
    assert await count(conn, "candidate") == 0 and await count(conn, "raw_batch") == 0
    assert not bs.root.exists() or not any(bs.root.rglob("*"))
    assert await get_cursor(conn, INFO.log_id) == (2, False)


async def test_live_emits_candidate_once_and_stores_raw(fake, ix, sup, bs, conn):
    await bootstrapped(conn)
    stats = StatCounter()
    n1 = await process_batch(fake, 0, 1, mode="live", ix=ix, sup=sup, bs=bs, conn=conn, stats=stats)
    n2 = await process_batch(fake, 2, 3, mode="live", ix=ix, sup=sup, bs=bs, conn=conn, stats=stats)
    assert (n1, n2) == (2, 2)
    assert await count(conn, "candidate") == len(EXPECTED_NEW_FQDNS)
    cur = await conn.execute("SELECT fqdn, log_index FROM candidate")
    rows = await cur.fetchall()
    assert {r[0] for r in rows} == EXPECTED_NEW_FQDNS
    assert {r[1] for r in rows} == {0, 1}
    assert await count(conn, "raw_batch") == 2

    cur = await conn.execute(
        "SELECT start_index, end_index, blob_sha256, entries FROM raw_batch ORDER BY start_index"
    )
    batches = await cur.fetchall()
    assert [(b[0], b[1], b[3]) for b in batches] == [(0, 1, 2), (2, 3, 2)]
    with bs.open(batches[1][2]) as f:
        assert unpack_entries(f.read()) == fake._entries[2:4]

    assert await get_cursor(conn, INFO.log_id) == (4, True)
    stat = await read_stat(conn, INFO.log_id, today())
    assert stat["entries"] == 4
    assert stat["certs_unique"] == 2
    assert stat["fqdns_new"] == 3
    assert stat["candidates"] == 3
    assert stat["suppressed"] == 0
    assert stat["parse_failed"] == 0
    assert stat["bytes"] == sum(len(l) + len(e) for _, l, e in fake._entries)
    assert stats.entries == 4 and stats.candidates == 3


async def test_cursor_advances_only_after_batch_commit(fake, ix, sup, tmp_path, cfg, conn):
    await bootstrapped(conn)
    fake_failing_blobstore = FailingBlobStore(tmp_path / "blobs")
    with pytest.raises(OSError):
        await tail_log_once(fake, cfg, ix, sup, fake_failing_blobstore, conn)
    assert await get_cursor(conn, fake.info.log_id) == (0, True)
    assert await count(conn, "candidate") == 0
    assert await count(conn, "raw_batch") == 0
    assert (await read_stat(conn, INFO.log_id, today()))["entries"] == 0
    # The index is only written after the commit, so a retry re-emits them.
    for fqdn in EXPECTED_NEW_FQDNS:
        assert ix.get(fqdn) is None
    assert await tail_log_once(fake, cfg, ix, sup, BlobStore(tmp_path / "blobs"), conn) == 2
    cur = await conn.execute("SELECT fqdn FROM candidate")
    assert {r[0] for r in await cur.fetchall()} == EXPECTED_NEW_FQDNS


async def test_rerun_of_committed_batch_emits_no_new_candidates(fake, ix, sup, bs, conn):
    await bootstrapped(conn)
    await process_batch(fake, 0, 1, mode="live", ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    # Simulate a restart that re-processes the same range (e.g. cursor rewound).
    await set_cursor(conn, INFO.log_id, 0, True)
    await conn.commit()
    await process_batch(fake, 0, 1, mode="live", ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    assert await count(conn, "candidate") == len(EXPECTED_NEW_FQDNS)
    assert await get_cursor(conn, INFO.log_id) == (2, True)


async def test_duplicates_within_one_batch_count_once(fake, ix, sup, bs, conn):
    await bootstrapped(conn)
    stats = StatCounter()
    await process_batch(fake, 0, 3, mode="live", ix=ix, sup=sup, bs=bs, conn=conn, stats=stats)
    assert await count(conn, "candidate") == len(EXPECTED_NEW_FQDNS)
    assert (stats.certs_unique, stats.fqdns_new) == (2, 3)
    cur = await conn.execute("SELECT DISTINCT log_index FROM candidate")
    assert {r[0] for r in await cur.fetchall()} == {0, 1}
    assert ix.get(EXPECTED_FQDN)[2] == 0


async def test_live_skips_candidates_until_bootstrap_done(ix, sup, bs, conn):
    src = FakeSource([LEAF_X509, LEAF_PRECERT, GARBAGE])
    n = await process_batch(src, 0, 2, mode="live", ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    assert n == 3
    assert await count(conn, "raw_batch") == 1
    assert await count(conn, "candidate") == 0
    stat = await read_stat(conn, INFO.log_id, today())
    assert stat["entries"] == 3
    assert stat["parse_failed"] == 1
    assert stat["fqdns_new"] == 3
    assert stat["candidates"] == 0
    assert await get_cursor(conn, INFO.log_id) == (3, False)


async def test_suppressed_names_are_indexed_not_candidates(fake, ix, bs, conn):
    await bootstrapped(conn)
    suppressed = "san0.9950eab53001792788541807.osu.prod.canaries.quickbeam.acm.aws.dev"
    sup = Suppressor(frozenset(), frozenset({suppressed}))
    await process_batch(fake, 0, 1, mode="live", ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    cur = await conn.execute("SELECT fqdn FROM candidate")
    assert {r[0] for r in await cur.fetchall()} == EXPECTED_NEW_FQDNS - {suppressed}
    assert ix.get(suppressed) is not None
    stat = await read_stat(conn, INFO.log_id, today())
    assert (stat["fqdns_new"], stat["suppressed"], stat["candidates"]) == (3, 1, 2)


async def test_bootstrap_log_walks_to_tree_size_and_marks_done(fake, ix, sup, bs, cfg, conn):
    await bootstrap_log(fake, cfg, ix, sup, bs, conn)
    assert await get_cursor(conn, INFO.log_id) == (4, True)
    assert fake.calls == [(0, 1), (2, 3)]
    assert await count(conn, "candidate") == 0 and await count(conn, "raw_batch") == 0
    assert ix.get(EXPECTED_FQDN) is not None
    # Already done: a second call does nothing.
    fake.calls.clear()
    await bootstrap_log(fake, cfg, ix, sup, bs, conn)
    assert fake.calls == []


async def test_bootstrap_log_starts_at_index_at(ix, sup, bs, cfg, conn):
    src = FakeSource([LEAF_X509, LEAF_PRECERT])
    cfg = Config(data_dir=cfg.data_dir, database_url="unused", bootstrap_days=0)
    # The fixture leaves are older than "now", so index_at(now) is the tree size.
    await bootstrap_log(src, cfg, ix, sup, bs, conn)
    assert src.calls == []
    assert await get_cursor(conn, INFO.log_id) == (2, True)


async def test_tail_log_once_batches_and_catches_up(fake, ix, sup, bs, cfg, conn):
    await bootstrapped(conn)
    assert await tail_log_once(fake, cfg, ix, sup, bs, conn) == 2
    assert await tail_log_once(fake, cfg, ix, sup, bs, conn) == 2
    assert await tail_log_once(fake, cfg, ix, sup, bs, conn) == 0
    assert fake.calls == [(0, 1), (2, 3)]
    assert await get_cursor(conn, INFO.log_id) == (4, True)


async def test_tail_log_stops_on_event(fake, ix, sup, bs, cfg, conn):
    await bootstrapped(conn)
    stop = asyncio.Event()
    task = asyncio.create_task(tail_log(fake, cfg, ix, sup, bs, conn, stop))
    # Poll the source, not the shared connection, until the tailer is caught up
    # (it has then asked for both batches and is sleeping on the stop event).
    for _ in range(200):
        if len(fake.calls) >= 2:
            break
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=2)
    assert await get_cursor(conn, INFO.log_id) == (4, True)


def test_missing_tranco_falls_back_to_empty_set(tmp_path, caplog):
    from hakapik.ingest import _load_suppressor
    from hakapik.names import normalize

    cfg = Config(data_dir=tmp_path, database_url="unused", public_apexes=("example.net",))
    with caplog.at_level("WARNING"):
        s = _load_suppressor(cfg)
    assert "tranco.csv" in caplog.text
    assert s.reason(normalize("www.google.com")) is None
    assert s.reason(normalize("example.net")) == "public_apex"


# --- run() lifecycle -------------------------------------------------------

class SlowFakeSource(FakeSource):
    """Yields to the loop on every fetch so sibling tasks overlap."""

    async def entries(self, start, end):
        await asyncio.sleep(0.05)
        return await super().entries(start, end)


@pytest.fixture
def two_logs(monkeypatch, tmp_path, conn):
    a = SlowFakeSource([LEAF_X509], dataclasses.replace(INFO, log_id="logA"))
    b = SlowFakeSource([LEAF_X509, LEAF_PRECERT], dataclasses.replace(INFO, log_id="logB"))
    by_id = {s.info.log_id: s for s in (a, b)}

    async def fake_lists(urls, client):
        return [a.info, b.info]

    monkeypatch.setattr(ingest, "fetch_log_lists", fake_lists)
    monkeypatch.setattr(ingest, "make_source", lambda info, client: by_id[info.log_id])
    cfg = Config(data_dir=tmp_path, database_url=os.environ["HAKAPIK_TEST_DB"], batch_size=1)
    return cfg, a, b


async def test_run_survives_one_log_failing_to_connect(two_logs, monkeypatch, conn):
    cfg, a, b = two_logs
    calls = 0

    async def flaky_connect(url):
        nonlocal calls
        calls += 1
        if calls == 2:  # 1st is migrate; 2nd is log A's task
            raise OSError("too many connections")
        return await real_connect(url)

    monkeypatch.setattr(ingest, "connect", flaky_connect)
    await ingest.run(cfg, "bootstrap")
    await conn.rollback()
    assert await get_cursor(conn, "logA") == (0, False)
    assert await get_cursor(conn, "logB") == (2, True)
    assert b.calls == [(0, 0), (1, 1)]
    with FirstSeenIndex(cfg.data_dir / "firstseen") as ix:
        assert ix.get(EXPECTED_FQDN) is not None
        for fqdn in EXPECTED_NEW_FQDNS:
            assert ix.get(fqdn) is not None


async def test_run_tail_skips_log_not_bootstrapped(two_logs, conn, caplog):
    cfg, a, b = two_logs
    # Neither log is bootstrapped: run(tail) must skip both and return.
    with caplog.at_level("ERROR"):
        await asyncio.wait_for(ingest.run(cfg, "tail"), timeout=5)
    await conn.rollback()
    assert a.calls == [] and b.calls == []
    assert await get_cursor(conn, "logA") == (0, False)
    assert caplog.text.count("not bootstrapped") == 2


class GappySource(FakeSource):
    """Returns entries whose indices skip: start, then start+2 (non-contiguous)."""

    async def entries(self, start, end):
        self.calls.append((start, end))
        out = [e for e in self._entries[start : end + 1] if (e[0] - start) % 2 == 0]
        return out


async def test_bootstrap_advances_by_last_returned_index(ix, sup, bs, conn, tmp_path):
    src = GappySource([LEAF_X509, LEAF_PRECERT, LEAF_X509, LEAF_PRECERT, LEAF_X509])
    cfg = Config(data_dir=tmp_path, database_url="unused", batch_size=3)
    await bootstrap_log(src, cfg, ix, sup, bs, conn)
    # 0..2 returns indices 0 and 2 -> next is 3 (not 0 + 2); 3..4 returns 3 only.
    assert src.calls == [(0, 2), (3, 4), (4, 4)]
    assert await get_cursor(conn, INFO.log_id) == (5, True)
