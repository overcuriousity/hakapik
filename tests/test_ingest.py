import asyncio
import dataclasses
import os
import signal
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

import hakapik.ingest as ingest
from hakapik.blobstore import BlobStore
from hakapik.config import Config
from hakapik.ct.loglist import LogInfo
from hakapik.db import connect as real_connect
from hakapik.db import get_cursor, read_stat, set_cursor
from hakapik.firstseen import FirstSeenIndex
from hakapik.ingest import (
    StatCounter,
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


async def cursor_at(conn, log_id=INFO.log_id, next_index=0):
    await set_cursor(conn, log_id, next_index)
    await conn.commit()


def today():
    return datetime.now(timezone.utc).date()


def test_pack_roundtrip():
    entries = [(0, b"leaf0", b""), (2**40, b"", b"extra"), (7, b"\x00" * 300, b"\x01")]
    assert unpack_entries(pack_entries(entries)) == entries
    assert unpack_entries(pack_entries([])) == []


async def test_batch_emits_candidate_once_and_stores_raw(fake, ix, sup, bs, conn):
    stats = StatCounter()
    n1 = await process_batch(fake, 0, 1, ix=ix, sup=sup, bs=bs, conn=conn, stats=stats)
    n2 = await process_batch(fake, 2, 3, ix=ix, sup=sup, bs=bs, conn=conn, stats=stats)
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

    assert await get_cursor(conn, INFO.log_id) == 4
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
    await cursor_at(conn)
    fake_failing_blobstore = FailingBlobStore(tmp_path / "blobs")
    with pytest.raises(OSError):
        await tail_log_once(fake, cfg, ix, sup, fake_failing_blobstore, conn)
    assert await get_cursor(conn, fake.info.log_id) == 0
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
    await process_batch(fake, 0, 1, ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    # Simulate a restart that re-processes the same range (e.g. cursor rewound).
    await cursor_at(conn)
    await process_batch(fake, 0, 1, ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    assert await count(conn, "candidate") == len(EXPECTED_NEW_FQDNS)
    assert await get_cursor(conn, INFO.log_id) == 2


async def test_duplicates_within_one_batch_count_once(fake, ix, sup, bs, conn):
    stats = StatCounter()
    await process_batch(fake, 0, 3, ix=ix, sup=sup, bs=bs, conn=conn, stats=stats)
    assert await count(conn, "candidate") == len(EXPECTED_NEW_FQDNS)
    assert (stats.certs_unique, stats.fqdns_new) == (2, 3)
    cur = await conn.execute("SELECT DISTINCT log_index FROM candidate")
    assert {r[0] for r in await cur.fetchall()} == {0, 1}
    assert ix.get(EXPECTED_FQDN)[2] == 0


async def test_batch_counts_parse_failures_and_emits_the_rest(ix, sup, bs, conn):
    src = FakeSource([LEAF_X509, LEAF_PRECERT, GARBAGE])
    n = await process_batch(src, 0, 2, ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    assert n == 3
    assert await count(conn, "raw_batch") == 1
    assert await count(conn, "candidate") == len(EXPECTED_NEW_FQDNS)
    stat = await read_stat(conn, INFO.log_id, today())
    assert stat["entries"] == 3
    assert stat["parse_failed"] == 1
    assert stat["fqdns_new"] == 3
    assert stat["candidates"] == 3
    assert await get_cursor(conn, INFO.log_id) == 3


async def test_suppressed_names_are_indexed_not_candidates(fake, ix, bs, conn):
    suppressed = "san0.9950eab53001792788541807.osu.prod.canaries.quickbeam.acm.aws.dev"
    sup = Suppressor(frozenset(), frozenset({suppressed}))
    await process_batch(fake, 0, 1, ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    cur = await conn.execute("SELECT fqdn FROM candidate")
    assert {r[0] for r in await cur.fetchall()} == EXPECTED_NEW_FQDNS - {suppressed}
    assert ix.get(suppressed) is not None
    stat = await read_stat(conn, INFO.log_id, today())
    assert (stat["fqdns_new"], stat["suppressed"], stat["candidates"]) == (3, 1, 2)
    assert (stat["supp_public_apex"], stat["supp_tranco"], stat["supp_wildcard"]) == (1, 0, 0)


async def test_tail_without_cursor_starts_at_tree_size(fake, ix, sup, bs, cfg, conn):
    assert await tail_log_once(fake, cfg, ix, sup, bs, conn) == 0
    assert fake.calls == []
    assert await get_cursor(conn, INFO.log_id) == 4
    assert await count(conn, "candidate") == 0


async def test_tail_log_once_batches_and_catches_up(fake, ix, sup, bs, cfg, conn):
    await cursor_at(conn)
    assert await tail_log_once(fake, cfg, ix, sup, bs, conn) == 2
    assert await tail_log_once(fake, cfg, ix, sup, bs, conn) == 2
    assert await tail_log_once(fake, cfg, ix, sup, bs, conn) == 0
    assert fake.calls == [(0, 1), (2, 3)]
    assert await get_cursor(conn, INFO.log_id) == 4


async def test_tail_log_stops_on_event(fake, ix, sup, bs, cfg, conn):
    await cursor_at(conn)
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
    assert await get_cursor(conn, INFO.log_id) == 4


class HangingSource(FakeSource):
    """A log stuck answering 429: tree_size never returns."""

    async def tree_size(self) -> int:
        await asyncio.Event().wait()


async def test_tail_log_stop_does_not_wait_for_a_hanging_log(ix, sup, bs, cfg, conn, monkeypatch):
    # A rate-limited log keeps retry_get sleeping (Retry-After up to 600 s);
    # the first stop signal must still end the tailer promptly.
    monkeypatch.setattr(ingest, "STOP_GRACE_S", 0.2)
    await cursor_at(conn)
    stop = asyncio.Event()
    task = asyncio.create_task(tail_log(HangingSource([LEAF_X509]), cfg, ix, sup, bs, conn, stop))
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=2)
    assert await get_cursor(conn, INFO.log_id) == 0


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


async def _stop_when(cond):
    """SIGTERM this process (run()'s stop signal) once ``cond()`` holds."""
    while not cond():
        await asyncio.sleep(0.01)
    os.kill(os.getpid(), signal.SIGTERM)


async def _run_until(cfg, cond):
    t = asyncio.create_task(_stop_when(cond))
    await asyncio.wait_for(ingest.run(cfg), timeout=5)
    await t


async def test_run_retries_log_that_failed_to_connect(two_logs, monkeypatch, conn, caplog):
    cfg, a, b = two_logs
    await cursor_at(conn, "logA")
    await cursor_at(conn, "logB")
    monkeypatch.setattr(ingest, "IDLE_SLEEP_S", 0.01)
    calls = 0

    async def flaky_connect(url):
        nonlocal calls
        calls += 1
        if calls == 2:  # 1st is migrate; 2nd is log A's first batch
            raise OSError("too many connections")
        return await real_connect(url)

    monkeypatch.setattr(ingest, "connect", flaky_connect)
    with caplog.at_level("WARNING"):
        await _run_until(cfg, lambda: len(a.calls) >= 1 and len(b.calls) >= 2)
    await conn.rollback()
    # Log A's first connection failed; the retry tailed it anyway, and log B
    # was not held up meanwhile.
    assert "batch failed: OSError('too many connections')" in caplog.text
    assert await get_cursor(conn, "logA") == 1
    assert await get_cursor(conn, "logB") == 2
    assert a.calls == [(0, 0)]
    assert b.calls == [(0, 0), (1, 1)]
    with FirstSeenIndex(cfg.data_dir / "firstseen") as ix:
        for fqdn in EXPECTED_NEW_FQDNS:
            assert ix.get(fqdn) is not None


class GrowingSource(SlowFakeSource):
    """Holds ``old`` entries at the first tree_size() call, ``old + new`` after.

    Records the log's cursor (read on ``conn``) at the first entries() call.
    """

    def __init__(self, old, new, info, conn):
        super().__init__(old + new, info)
        self._visible = len(old)
        self._conn = conn
        self.cursor_at_first_fetch = "unset"

    async def tree_size(self):
        size = self._visible
        self._visible = len(self._entries)
        return size

    async def entries(self, start, end):
        if self.cursor_at_first_fetch == "unset":
            self.cursor_at_first_fetch = await get_cursor(self._conn, self.info.log_id)
            await self._conn.rollback()
        return await super().entries(start, end)


async def test_run_starts_new_log_at_tree_size_and_emits_from_first_batch(
    tmp_path, monkeypatch, conn
):
    info = dataclasses.replace(INFO, log_id="newlog")
    # The same two certs before and after the tip: had the old ones been
    # read, the new ones would not be first sightings.
    src = GrowingSource([LEAF_X509, LEAF_PRECERT], [LEAF_X509, LEAF_PRECERT], info, conn)

    async def fake_lists(urls, client):
        return [info]

    monkeypatch.setattr(ingest, "fetch_log_lists", fake_lists)
    monkeypatch.setattr(ingest, "make_source", lambda i, client: src)
    monkeypatch.setattr(ingest, "IDLE_SLEEP_S", 0.01)
    cfg = Config(data_dir=tmp_path, database_url=os.environ["HAKAPIK_TEST_DB"], batch_size=2)
    await _run_until(cfg, lambda: len(src.calls) >= 1)
    await conn.rollback()
    assert src.cursor_at_first_fetch == 2  # cursor row written before tailing
    assert src.calls == [(2, 3)]  # nothing before the tip is fetched
    assert await get_cursor(conn, "newlog") == 4
    cur = await conn.execute("SELECT fqdn, log_index FROM candidate")
    rows = await cur.fetchall()
    assert {r[0] for r in rows} == EXPECTED_NEW_FQDNS
    assert {r[1] for r in rows} == {2, 3}


async def test_run_sets_user_agent(two_logs, monkeypatch, conn):
    cfg, a, b = two_logs
    seen = []

    async def fake_lists(urls, client):
        seen.append(client.headers["User-Agent"])
        return []

    monkeypatch.setattr(ingest, "fetch_log_lists", fake_lists)
    await ingest.run(cfg)
    assert seen == ["hakapik/0.1 (CT monitor)"]


async def test_run_caps_open_db_connections(two_logs, monkeypatch, conn):
    cfg, a, b = two_logs
    cfg = dataclasses.replace(cfg, max_db_connections=1)
    await cursor_at(conn, "logA")
    await cursor_at(conn, "logB")
    monkeypatch.setattr(ingest, "IDLE_SLEEP_S", 0.01)
    open_now = peak = 0

    class Tracked:
        def __init__(self, c):
            self._c = c

        def __getattr__(self, name):
            return getattr(self._c, name)

        async def close(self):
            nonlocal open_now
            if not self._c.closed:
                open_now -= 1
            await self._c.close()

    async def tracking_connect(url):
        nonlocal open_now, peak
        c = await real_connect(url)
        open_now += 1
        peak = max(peak, open_now)
        return Tracked(c)

    monkeypatch.setattr(ingest, "connect", tracking_connect)
    await _run_until(cfg, lambda: len(a.calls) >= 1 and len(b.calls) >= 2)
    await conn.rollback()
    assert peak == 1 and open_now == 0
    assert await get_cursor(conn, "logA") == 1
    assert await get_cursor(conn, "logB") == 2


class GappySource(FakeSource):
    """Returns entries whose indices skip: start, then start+2 (non-contiguous)."""

    async def entries(self, start, end):
        self.calls.append((start, end))
        out = [e for e in self._entries[start : end + 1] if (e[0] - start) % 2 == 0]
        return out


async def test_tail_advances_by_last_returned_index(ix, sup, bs, conn, tmp_path):
    src = GappySource([LEAF_X509, LEAF_PRECERT, LEAF_X509, LEAF_PRECERT, LEAF_X509])
    await cursor_at(conn)
    cfg = Config(data_dir=tmp_path, database_url="unused", batch_size=3)
    while await tail_log_once(src, cfg, ix, sup, bs, conn):
        pass
    # 0..2 returns indices 0 and 2 -> next is 3 (not 0 + 2); 3..4 returns 3 only.
    assert src.calls == [(0, 2), (3, 4), (4, 4)]
    assert await get_cursor(conn, INFO.log_id) == 5


# --- wildcard vs apex (synthetic leaves) ------------------------------------

from hakapik.ct.leaf import ParsedLeaf

_DT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _synth(serial: str, *sans: str) -> bytes:
    return f"{serial}|{','.join(sans)}".encode()


@pytest.fixture
def synth(monkeypatch):
    """Make _parse decode b"serial|san1,san2" leaves into ParsedLeaf records."""

    def parse(kind, leaf):
        serial, sans = leaf.decode().split("|")
        return ParsedLeaf(
            1000, "x509", b"issuer", serial.encode(), tuple(sans.split(",")), _DT, _DT, len(leaf)
        )

    monkeypatch.setattr(ingest, "_parse", parse)


async def _candidates(conn) -> set[str]:
    cur = await conn.execute("SELECT fqdn FROM candidate")
    return {r[0] for r in await cur.fetchall()}


async def test_wildcard_first_does_not_hide_apex(synth, ix, sup, bs, conn):
    src = FakeSource([_synth("1", "*.a.com", "a.com")])
    stats = StatCounter()
    await process_batch(src, 0, 0, ix=ix, sup=sup, bs=bs, conn=conn, stats=stats)
    assert await _candidates(conn) == {"a.com"}
    assert (stats.fqdns_new, stats.suppressed, stats.candidates) == (2, 1, 1)
    assert ix.get("*.a.com") is not None and ix.get("a.com") is not None


async def test_wildcard_only_cert_then_apex_cert_emits_apex(synth, ix, sup, bs, conn):
    src = FakeSource([_synth("1", "*.b.com"), _synth("2", "b.com")])
    await process_batch(src, 0, 0, ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    assert await _candidates(conn) == set()
    await process_batch(src, 1, 1, ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    assert await _candidates(conn) == {"b.com"}


# --- tiled logs: batches end on tile boundaries -----------------------------

from hakapik.ct.leaf import parse_tile_leaf

TILE_FIX = FIX / "tile_data_small.bin"
TILED_INFO = dataclasses.replace(INFO, log_id="tiledlog", kind="tiled", monitoring_url="https://t.invalid/")


def _tile_leaves(n: int) -> list[bytes]:
    buf = memoryview(TILE_FIX.read_bytes())
    pool, off = [], 0
    while off < len(buf):
        _, nxt = parse_tile_leaf(buf, off)
        pool.append(bytes(buf[off:nxt]))
        off = nxt
    return [pool[i % len(pool)] for i in range(n)]


class TiledFakeSource(FakeSource):
    def __init__(self, n: int):
        super().__init__(_tile_leaves(n), TILED_INFO)
        self._entries = [(i, leaf, b"") for i, leaf, _ in self._entries]


async def test_tail_tiled_batches_are_tile_aligned(ix, sup, bs, tmp_path, conn):
    src = TiledFakeSource(600)
    await cursor_at(conn, TILED_INFO.log_id, 100)
    cfg = Config(data_dir=tmp_path, database_url="unused", batch_size=256)
    while await tail_log_once(src, cfg, ix, sup, bs, conn):
        pass
    assert src.calls == [(100, 255), (256, 511), (512, 599)]
    assert await get_cursor(conn, TILED_INFO.log_id) == 600
    assert await count(conn, "raw_batch") == 3


async def test_tail_tiled_batch_size_spans_whole_tiles(ix, sup, bs, tmp_path, conn):
    src = TiledFakeSource(1200)
    await cursor_at(conn, TILED_INFO.log_id, 100)
    cfg = Config(data_dir=tmp_path, database_url="unused", batch_size=512)
    while await tail_log_once(src, cfg, ix, sup, bs, conn):
        pass
    assert src.calls == [(100, 511), (512, 1023), (1024, 1199)]
    cfg = Config(data_dir=tmp_path, database_url="unused", batch_size=10)
    assert ingest._batch_end(src, 0, 1200, cfg.batch_size) == 255  # at least one tile


async def test_stats_split_by_reason(synth, ix, bs, conn):
    sup = Suppressor(frozenset({"t.com"}), frozenset({"pub.com"}))
    src = FakeSource([
        _synth("1", "t.com", "x.com"),
        _synth("2", "www.t.com", "*.w.com", "pub.com", "y.com"),
    ])
    await process_batch(src, 0, 0, ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    await process_batch(src, 1, 1, ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    stat = await read_stat(conn, INFO.log_id, today())
    assert (stat["entries"], stat["fqdns_new"], stat["suppressed"]) == (2, 6, 4)
    assert (stat["supp_tranco"], stat["supp_wildcard"], stat["supp_public_apex"]) == (2, 1, 1)
    assert stat["candidates"] == 2
    assert await _candidates(conn) == {"x.com", "y.com"}


# --- tail logging -----------------------------------------------------------

async def test_tail_log_logs_rate_and_lag(fake, ix, sup, bs, cfg, conn, monkeypatch, caplog):
    await cursor_at(conn)
    monkeypatch.setattr(ingest, "PROGRESS_INTERVAL_S", 0.0)
    stop = asyncio.Event()
    with caplog.at_level("INFO"):
        task = asyncio.create_task(tail_log(fake, cfg, ix, sup, bs, conn, stop))
        for _ in range(200):
            if "lag=0" in caplog.text:
                break
            await asyncio.sleep(0.01)
        stop.set()
        await asyncio.wait_for(task, timeout=2)
    assert "entries/s lag=2 next_index=2 tree_size=4" in caplog.text
    assert "lag=0 next_index=4 tree_size=4" in caplog.text


async def test_tail_log_rate_limits_tracebacks(ix, sup, bs, cfg, conn, monkeypatch, caplog):
    monkeypatch.setattr(ingest, "IDLE_SLEEP_S", 0.001)

    class Broken(FakeSource):
        tries = 0

        async def tree_size(self):
            Broken.tries += 1
            raise httpx.ConnectError("down")

    stop = asyncio.Event()
    with caplog.at_level("WARNING"):
        task = asyncio.create_task(tail_log(Broken([]), cfg, ix, sup, bs, conn, stop))
        while Broken.tries < 5:
            await asyncio.sleep(0.005)
        stop.set()
        await asyncio.wait_for(task, timeout=2)
    recs = [r for r in caplog.records if "batch failed" in r.getMessage()]
    assert len(recs) >= 5 and all(r.levelname == "WARNING" for r in recs)
    assert "ConnectError('down')" in recs[0].getMessage()
    assert [bool(r.exc_info) for r in recs].count(True) == 1 and recs[0].exc_info


async def test_tail_log_lag_never_negative(ix, sup, bs, cfg, conn, monkeypatch, caplog):
    # A log whose tree head lags the entries it serves: cursor ahead of size.
    await cursor_at(conn, INFO.log_id, 6)
    fake = FakeSource([b"x"] * 4)
    monkeypatch.setattr(ingest, "PROGRESS_INTERVAL_S", 0.0)
    stop = asyncio.Event()
    with caplog.at_level("INFO"):
        task = asyncio.create_task(tail_log(fake, cfg, ix, sup, bs, conn, stop))
        for _ in range(200):
            if "lag=" in caplog.text:
                break
            await asyncio.sleep(0.01)
        stop.set()
        await asyncio.wait_for(task, timeout=2)
    assert "lag=0 next_index=6 tree_size=4 (tree head 2 behind served entries)" in caplog.text
    assert "lag=-" not in caplog.text


# --- readonly logs ----------------------------------------------------------

READONLY_INFO = dataclasses.replace(INFO, log_id="rolog", state="readonly")


async def test_readonly_log_without_cursor_is_not_tailed(ix, sup, bs, cfg, conn, caplog):
    src = FakeSource([b"x"] * 4, READONLY_INFO)
    with caplog.at_level("INFO"):
        await asyncio.wait_for(tail_log(src, cfg, ix, sup, bs, conn, asyncio.Event()), 2)
    assert src.calls == []
    assert await get_cursor(conn, READONLY_INFO.log_id) is None
    assert "skipped (readonly, no cursor)" in caplog.text


async def test_readonly_log_with_cursor_reads_to_size_then_returns(
    ix, sup, bs, cfg, conn, caplog
):
    src = FakeSource([b"x"] * 4, READONLY_INFO)
    await cursor_at(conn, READONLY_INFO.log_id, 1)
    with caplog.at_level("INFO"):
        await asyncio.wait_for(tail_log(src, cfg, ix, sup, bs, conn, asyncio.Event()), 5)
    assert src.calls and src.calls[0][0] == 1 and src.calls[-1][1] == 3
    assert await get_cursor(conn, READONLY_INFO.log_id) == 4
    assert "following until caught up (readonly, 3 entries left)" in caplog.text
    assert "caught up (readonly)" in caplog.text


async def test_usable_log_keeps_running_when_caught_up(ix, sup, bs, cfg, conn):
    src = FakeSource([b"x"] * 2)
    await cursor_at(conn, INFO.log_id, 2)
    stop = asyncio.Event()
    task = asyncio.create_task(tail_log(src, cfg, ix, sup, bs, conn, stop))
    await asyncio.sleep(0.2)
    assert not task.done()
    stop.set()
    await asyncio.wait_for(task, 2)


@pytest.mark.parametrize("cursor", [4, 9])
async def test_readonly_log_cursor_at_or_beyond_size_returns_at_once(
    ix, sup, bs, cfg, conn, caplog, cursor
):
    src = FakeSource([b"x"] * 4, READONLY_INFO)
    await cursor_at(conn, READONLY_INFO.log_id, cursor)
    with caplog.at_level("INFO"):
        await asyncio.wait_for(tail_log(src, cfg, ix, sup, bs, conn, asyncio.Event()), 1)
    assert src.calls == []
    assert "caught up (readonly)" in caplog.text
    assert await get_cursor(conn, READONLY_INFO.log_id) == cursor
