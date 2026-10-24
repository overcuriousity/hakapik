"""Per-log ingest: the per-batch pipeline and the live tail.

A log without a cursor row starts at its current tree size: ingest only ever
reads forward from the moment a log is first tailed, never its history.

Transaction boundary: one Postgres transaction per batch. Candidates, the
raw_batch row, the stats increments and the cursor advance commit together,
or not at all. The batch decides novelty by *reading* the first-seen index
(RocksDB) plus per-batch sets; the index writes are collected in memory and
applied only after the commit succeeds. Consequences:

- A failure before or during the commit rolls back the DB and leaves the
  index untouched, so the retry re-emits the same candidates (none lost).
- A crash between the commit and the index writes leaves those FQDNs absent
  from the index although their candidates are committed. The next
  certificate naming such an FQDN can then emit a duplicate candidate; a
  candidate is never lost. Later stages dedup candidates by fqdn.
- Re-running an already committed and indexed batch emits nothing new.

The raw blob is written before the commit; after a failure it may be an
orphan (harmless: content-addressed, reclaimed by pruning).

Concurrency: one in-flight batch per log. Log tasks share one
``FirstSeenIndex`` on one event loop and borrow Postgres connections from a
``ConnPool`` capped at ``Config.max_db_connections``. Two logs can both read an FQDN as new before either applies its
post-commit writes (a batch awaits the DB in between); that too yields at
most a duplicate candidate, and ``first_seen`` keeps the first writer's
sighting.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import struct
import time
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import zstandard

from hakapik.blobstore import BlobStore
from hakapik.config import Config
from hakapik.ct.leaf import LeafError, parse_rfc6962_leaf, parse_tile_leaf
from hakapik.ct.loglist import fetch_log_lists
from hakapik.ct.source import LogSource, make_source
from hakapik.ct.static_ct import TILE_WIDTH
from hakapik.db import (
    CandidateRow,
    add_candidates,
    add_raw_batch,
    bump_stat,
    connect,
    get_cursor,
    init_cursor,
    migrate,
    set_cursor,
)
from hakapik.dedup import cert_key
from hakapik.firstseen import FirstSeenIndex
from hakapik.jobs import last_fetched
from hakapik.names import NameRecord, normalize
from hakapik.suppress import Suppressor

RAW_MEDIA_TYPE = "application/x-hakapik-ctbatch"
USER_AGENT = "hakapik/0.1 (CT monitor)"
IDLE_SLEEP_S = 10.0
PROGRESS_INTERVAL_S = 60.0  # per-log rate/lag log line
TRACEBACK_INTERVAL_S = 600.0  # at most one full traceback per log per window
STOP_GRACE_S = 5.0  # after stop, a running batch may finish this long, then is cancelled

_HEAD = struct.Struct(">QI")
_LEN = struct.Struct(">I")


def _logger(src: LogSource) -> logging.Logger:
    return logging.getLogger(f"hakapik.ingest.{src.info.log_id}")


@dataclass
class StatCounter:
    entries: int = 0
    bytes: int = 0
    parse_failed: int = 0
    certs_unique: int = 0
    fqdns_new: int = 0
    suppressed: int = 0  # total; supp_* split it by Suppressor.reason()
    supp_tranco: int = 0
    supp_public_apex: int = 0
    supp_wildcard: int = 0
    # candidates counts first-seen candidates only; re-check candidates are
    # counted apart in candidates_recheck, so day-one numbers stay comparable.
    candidates: int = 0
    candidates_recheck: int = 0

    def increments(self) -> dict[str, int]:
        return asdict(self)

    def add(self, other: StatCounter) -> None:
        for f in fields(self):
            setattr(self, f.name, getattr(self, f.name) + getattr(other, f.name))


def pack_entries(entries: list[tuple[int, bytes, bytes]]) -> bytes:
    """Pack (index, leaf, extra) records and zstd-compress them.

    Record layout (big-endian): uint64 index, uint32 leaf_len, leaf,
    uint32 extra_len, extra.
    """
    parts: list[bytes] = []
    for index, leaf, extra in entries:
        parts += (_HEAD.pack(index, len(leaf)), leaf, _LEN.pack(len(extra)), extra)
    return zstandard.ZstdCompressor().compress(b"".join(parts))


def unpack_entries(data: bytes) -> list[tuple[int, bytes, bytes]]:
    raw = zstandard.ZstdDecompressor().decompress(data)
    out: list[tuple[int, bytes, bytes]] = []
    pos = 0
    while pos < len(raw):
        index, leaf_len = _HEAD.unpack_from(raw, pos)
        pos += _HEAD.size
        leaf = raw[pos : pos + leaf_len]
        pos += leaf_len
        (extra_len,) = _LEN.unpack_from(raw, pos)
        pos += _LEN.size
        extra = raw[pos : pos + extra_len]
        pos += extra_len
        out.append((index, leaf, extra))
    return out


def _batch_end(src: LogSource, pos: int, size: int, batch_size: int) -> int:
    """Inclusive end index of the batch starting at ``pos``.

    Tiled logs serve whole 256-entry tiles, so their batches end on a tile
    boundary (each tile is fetched once) and span ``batch_size // 256`` tiles,
    at least one; other logs use ``batch_size``.
    """
    if src.info.kind == "tiled":
        tiles = max(1, batch_size // TILE_WIDTH)
        return min((pos // TILE_WIDTH + tiles) * TILE_WIDTH, size) - 1
    return min(pos + batch_size, size) - 1


def _parse(kind: str, leaf: bytes):
    if kind == "tiled":
        return parse_tile_leaf(memoryview(leaf), 0)[0]
    return parse_rfc6962_leaf(leaf)


async def process_batch(
    src: LogSource,
    start: int,
    end: int,
    *,
    ix: FirstSeenIndex,
    sup: Suppressor,
    bs: BlobStore,
    conn,
    stats: StatCounter,
    recheck_days: int = 30,
) -> int:
    """Ingest entries start..end; return how many entries the log returned.

    See ``_process_batch`` for the details.
    """
    n, _ = await _process_batch(
        src, start, end, ix=ix, sup=sup, bs=bs, conn=conn, stats=stats,
        recheck_days=recheck_days,
    )
    return n


async def _process_batch(
    src: LogSource,
    start: int,
    end: int,
    *,
    ix: FirstSeenIndex,
    sup: Suppressor,
    bs: BlobStore,
    conn,
    stats: StatCounter,
    recheck_days: int,
) -> tuple[int, int]:
    """Ingest entries start..end; return (entries returned, next cursor index).

    The log may return fewer entries than asked for (always a prefix starting
    at ``start``); the cursor then advances past what was returned only. On
    success the batch's counts are also added to ``stats`` (a running total).
    """
    log_id = src.info.log_id
    try:
        entries = await src.entries(start, end)
        if not entries:
            return 0, start
        batch = StatCounter(entries=len(entries))
        rows: list[CandidateRow] = []
        new_certs: set[bytes] = set()
        new_fqdns: dict[str, tuple[int, int]] = {}  # NameRecord.key -> (ts_ms, index)
        # Already-indexed, unsuppressed names seen again: re-check contenders.
        recheck: dict[str, tuple[NameRecord, int, int, bytes]] = {}
        for index, leaf, extra in entries:
            batch.bytes += len(leaf) + len(extra)
            parsed = _parse(src.info.kind, leaf)
            if isinstance(parsed, LeafError):
                batch.parse_failed += 1
                continue
            key = cert_key(parsed.issuer_dn_der, parsed.serial)
            if key in new_certs or ix.has_cert(key):
                continue
            new_certs.add(key)
            batch.certs_unique += 1
            for san in parsed.san_dns:
                rec = normalize(san)
                if not rec.valid:
                    continue  # never indexed or emitted
                if rec.key in new_fqdns:
                    continue
                if ix.get(rec.key) is not None:
                    if (
                        not rec.wildcard
                        and rec.fqdn not in recheck
                        and sup.reason(rec) is None
                    ):
                        recheck[rec.fqdn] = (rec, parsed.timestamp_ms, index, key)
                    continue
                new_fqdns[rec.key] = (parsed.timestamp_ms, index)
                batch.fqdns_new += 1
                reason = sup.reason(rec)
                if reason is not None:
                    batch.suppressed += 1
                    by_reason = f"supp_{reason}"
                    if hasattr(batch, by_reason):
                        setattr(batch, by_reason, getattr(batch, by_reason) + 1)
                else:
                    rows.append(
                        CandidateRow(
                            rec.fqdn, rec.registrable, log_id, index, key,
                            parsed.timestamp_ms,
                        )
                    )
        batch.candidates = len(rows)
        if recheck:
            last_at = await last_fetched(conn, list(recheck))
            cutoff = datetime.now(timezone.utc) - timedelta(days=recheck_days)
            for fqdn, (rec, ts_ms, index, key) in recheck.items():
                done = last_at.get(fqdn)  # never attempted: not re-checked
                if done is None or done >= cutoff or sup.top_listed(rec.registrable):
                    continue
                rows.append(
                    CandidateRow(
                        fqdn, rec.registrable, log_id, index, key, ts_ms, "recheck"
                    )
                )
                batch.candidates_recheck += 1
        last = entries[-1][0]
        blob = bs.put(pack_entries(entries), RAW_MEDIA_TYPE)
        await add_raw_batch(conn, log_id, start, last, blob, len(entries), batch.bytes)
        await add_candidates(conn, rows)
        day = datetime.now(timezone.utc).date()
        await bump_stat(conn, log_id, day, **batch.increments())
        await set_cursor(conn, log_id, last + 1)
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    # Committed: now record what this batch saw (see the module docstring).
    for key in new_certs:
        ix.seen_cert(key)
    for fqdn, (ts_ms, index) in new_fqdns.items():
        ix.first_seen(fqdn, ts_ms, log_id, index)
    stats.add(batch)
    return len(entries), last + 1


class _Progress:
    """Logs a log's entries/s and lag once per PROGRESS_INTERVAL_S."""

    def __init__(self, log: logging.Logger):
        self._log = log
        self._t0 = time.monotonic()
        self._n = 0

    def note(self, n: int, next_index: int, size: int) -> None:
        self._n += n
        dt = time.monotonic() - self._t0
        if dt < PROGRESS_INTERVAL_S:
            return
        rate = self._n / dt if dt > 0 else 0.0
        # next_index > size happens when a log's tree head (STH/checkpoint)
        # lags behind the entries it already serves; the lag is then 0.
        ahead = next_index - size
        self._log.info(
            "tail %.1f entries/s lag=%d next_index=%d tree_size=%d%s",
            rate, max(0, -ahead), next_index, size,
            f" (tree head {ahead} behind served entries)" if ahead > 0 else "",
        )
        self._t0 = time.monotonic()
        self._n = 0


class _Failures:
    """WARNING per failure; full traceback on the first, then once per window."""

    def __init__(self, log: logging.Logger):
        self._log = log
        self._last_tb: float | None = None

    def warn(self, what: str, exc: BaseException, retry_s: float) -> None:
        now = time.monotonic()
        tb = self._last_tb is None or now - self._last_tb >= TRACEBACK_INTERVAL_S
        if tb:
            self._last_tb = now
        self._log.warning(
            "%s failed: %r; retrying in %.0f s", what, exc, retry_s,
            exc_info=exc if tb else None,
        )


class ConnPool:
    """Postgres connections shared by the log tasks, opened lazily.

    At most ``size`` connections exist (and are held) at once; a task waits
    for one in ``borrow()``. A connection that fails is closed and replaced.
    """

    def __init__(self, url: str, size: int):
        self._url = url
        self._sem = asyncio.Semaphore(size)
        self._idle: list = []

    @contextlib.asynccontextmanager
    async def borrow(self):
        async with self._sem:
            conn = self._idle.pop() if self._idle else await connect(self._url)
            try:
                yield conn
            except Exception:
                await self._release(conn)
                raise
            except BaseException:  # cancelled: do not await the server
                with contextlib.suppress(Exception):
                    await conn.close()
                raise
            await self._release(conn)

    async def _release(self, conn) -> None:
        if not (conn.closed or conn.broken):
            try:
                await conn.rollback()  # no-op unless a transaction is open
                self._idle.append(conn)
                return
            except Exception:
                pass
        with contextlib.suppress(Exception):
            await conn.close()

    async def close(self) -> None:
        while self._idle:
            await self._idle.pop().close()


def _borrow(db):
    """A connection from a ``ConnPool``, or a plain connection as is."""
    return db.borrow() if isinstance(db, ConnPool) else contextlib.nullcontext(db)


async def _tail_once(
    src: LogSource, cfg: Config, ix: FirstSeenIndex, sup: Suppressor, bs: BlobStore, conn
) -> tuple[int, int, int]:
    """One live batch from the cursor; return (entries, next index, tree size).

    A log without a cursor row gets one at the current tree size, committed
    before any entry is fetched (nothing before it is ever read).
    """
    log_id = src.info.log_id
    next_index = await get_cursor(conn, log_id)
    await conn.rollback()
    size = await src.tree_size()
    if next_index is None:
        try:
            created = await init_cursor(conn, log_id, size)
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise
        if created:
            _logger(src).info("no cursor; starting at tree_size=%d", size)
            return 0, size, size
        # Another process created the cursor first; its value stands.
        existing = await get_cursor(conn, log_id)
        await conn.rollback()
        return 0, size if existing is None else existing, size
    if next_index >= size:
        return 0, next_index, size
    end = _batch_end(src, next_index, size, cfg.batch_size)
    n, nxt = await _process_batch(
        src, next_index, end, ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter(),
        recheck_days=cfg.recheck_days,
    )
    return n, nxt, size


async def tail_log_once(
    src: LogSource, cfg: Config, ix: FirstSeenIndex, sup: Suppressor, bs: BlobStore, conn
) -> int:
    """Process one live batch from the cursor; return entries processed."""
    return (await _tail_once(src, cfg, ix, sup, bs, conn))[0]


async def _sleep_or_stop(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), seconds)
    except TimeoutError:
        pass


async def tail_log(
    src: LogSource,
    cfg: Config,
    ix: FirstSeenIndex,
    sup: Suppressor,
    bs: BlobStore,
    db,
    stop: asyncio.Event,
) -> None:
    """Tail the log until ``stop`` is set; errors are logged and retried.

    ``db`` is a ``ConnPool`` (a connection is borrowed per batch) or a
    connection. Logs entries/s and lag every PROGRESS_INTERVAL_S.

    A readonly log no longer grows, so it is not tailed without a cursor
    (it would start at its tree size and never yield an entry); with a cursor
    it is followed until the cursor reaches the tree size, then this returns.
    """
    log = _logger(src)
    progress = _Progress(log)
    failures = _Failures(log)
    readonly = src.info.state == "readonly"
    while readonly and not stop.is_set():
        try:
            async with _borrow(db) as conn:
                cursor = await get_cursor(conn, src.info.log_id)
                await conn.rollback()
            size = 0
            if cursor is not None:
                # Stop-aware like a batch: retry_get can wait minutes on 429/5xx.
                # (The first batch asks for the tree size again; sharing it
                # would change _tail_once's signature for one request.)
                probe = asyncio.create_task(src.tree_size())
                if not await _finish_or_stop(probe, stop):
                    return
                size = probe.result()
        except Exception as e:
            failures.warn("readonly check", e, IDLE_SLEEP_S)
            await _sleep_or_stop(stop, IDLE_SLEEP_S)
            continue
        # A cursor that appears after this read was made by another process,
        # which then tails the log; skipping here is right. Cursors are never
        # deleted, so one seen here is still there for the batches below.
        if cursor is None:
            log.info("skipped (readonly, no cursor)")
            return
        if cursor >= size:
            log.info("caught up (readonly)")
            return
        log.info("following until caught up (readonly, %d entries left)", size - cursor)
        break
    async def one_batch():
        async with _borrow(db) as conn:
            return await _tail_once(src, cfg, ix, sup, bs, conn)

    while not stop.is_set():
        batch = asyncio.create_task(one_batch())
        if not await _finish_or_stop(batch, stop):
            return  # stopped mid-batch; nothing was committed, nothing skipped
        try:
            n, next_index, size = batch.result()
            progress.note(n, next_index, size)
            if readonly and next_index >= size:
                # No final progress.note(): this line and the one above carry
                # the end state, and a rate over the last partial interval
                # would say nothing useful about a log that has stopped.
                log.info("caught up (readonly)")
                return
        except Exception as e:
            failures.warn("batch", e, IDLE_SLEEP_S)
            n = 0
        if n == 0:
            await _sleep_or_stop(stop, IDLE_SLEEP_S)


async def _finish_or_stop(task: asyncio.Task, stop: asyncio.Event) -> bool:
    """Wait for ``task``; True once it is done, False if stop ended it.

    A log stuck in rate limiting keeps a batch in retry_get for up to
    Retry-After (600 s), so a set ``stop`` gives the batch STOP_GRACE_S to
    commit and then cancels it. Cancelling is safe: the cursor advances only
    with the batch's commit, so the next run repeats the batch.
    """
    stopper = asyncio.create_task(stop.wait())
    try:
        await asyncio.wait({task, stopper}, return_when=asyncio.FIRST_COMPLETED)
        if not task.done():
            await asyncio.wait({task}, timeout=STOP_GRACE_S)
    finally:
        stopper.cancel()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    return not task.cancelled()


def _load_suppressor(cfg: Config) -> Suppressor:
    tranco = cfg.data_dir / "tranco.csv"
    if tranco.exists():
        return Suppressor.from_files(tranco, cfg.tranco_top_n, cfg.public_apexes)
    logging.getLogger(__name__).warning("%s missing; Tranco suppression disabled", tranco)
    # An empty file gives an empty Tranco set but keeps the public apexes.
    return Suppressor.from_files(Path(os.devnull), 0, cfg.public_apexes)


async def run(cfg: Config) -> None:
    """Tail every active log, one task per log.

    A log seen for the first time starts at its current tree size (see
    ``_tail_once``). The tasks share one HTTP client, one first-seen index and
    a ``ConnPool`` of at most ``cfg.max_db_connections`` connections.
    SIGINT/SIGTERM set the stop event (tail stops between batches); a second
    signal cancels the run.
    """
    root = logging.getLogger(__name__)
    sup = _load_suppressor(cfg)
    bs = BlobStore(cfg.data_dir / "blobs")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    main = asyncio.current_task()

    def on_signal() -> None:
        if stop.is_set() and main is not None:
            main.cancel()
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, on_signal)
    pool = ConnPool(cfg.database_url, cfg.max_db_connections)
    try:
        conn = await connect(cfg.database_url)
        try:
            await migrate(conn)
        finally:
            await conn.close()

        async with httpx.AsyncClient(
            timeout=60, headers={"User-Agent": USER_AGENT}
        ) as client:
            logs = await fetch_log_lists(cfg.log_lists, client)
            root.info("%d active logs", len(logs))
            with FirstSeenIndex(cfg.data_dir / "firstseen") as ix:

                async def one(info) -> None:
                    # Never raises: a failing log must not end gather() early,
                    # which would close the shared index and client under the
                    # sibling tasks still using them.
                    log = logging.getLogger(f"hakapik.ingest.{info.log_id}")
                    try:
                        src = make_source(info, client)
                        await tail_log(src, cfg, ix, sup, bs, pool, stop)
                    except Exception:
                        log.exception("log task failed (%s)", info.description)

                results = await asyncio.gather(
                    *(one(info) for info in logs), return_exceptions=True
                )
                for info, res in zip(logs, results):
                    if isinstance(res, BaseException):
                        root.error("log task %s escaped: %r", info.log_id, res)
    finally:
        await pool.close()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)
