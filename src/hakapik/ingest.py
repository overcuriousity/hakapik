"""Per-log ingest: the per-batch pipeline, the bootstrap walk and the live tail.

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

Concurrency: one in-flight batch per log. ``Config.per_log_concurrency`` is
reserved and not used. Log tasks share one ``FirstSeenIndex`` on one event
loop and borrow Postgres connections from a ``ConnPool`` capped at
``Config.max_db_connections``. Two logs can both read an FQDN as new before either applies its
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

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
    bootstrapped_logs,
    bump_stat,
    connect,
    get_cursor,
    migrate,
    set_cursor,
)
from hakapik.dedup import cert_key
from hakapik.firstseen import FirstSeenIndex
from hakapik.names import normalize
from hakapik.suppress import Suppressor

RAW_MEDIA_TYPE = "application/x-hakapik-ctbatch"
USER_AGENT = "hakapik/0.1 (CT monitor)"
IDLE_SLEEP_S = 10.0
PROGRESS_INTERVAL_S = 60.0  # per-log rate/lag log line
TRACEBACK_INTERVAL_S = 600.0  # at most one full traceback per log per window
BOOTSTRAP_RETRY_BASE_S = 1.0
BOOTSTRAP_RETRY_MAX_S = 300.0

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
    candidates: int = 0

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

    Tiled logs serve whole 256-entry tiles, so their batches end at the next
    tile boundary (each tile is fetched once); other logs use ``batch_size``.
    """
    if src.info.kind == "tiled":
        return min((pos // TILE_WIDTH + 1) * TILE_WIDTH, size) - 1
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
    mode: Literal["bootstrap", "live"],
    ix: FirstSeenIndex,
    sup: Suppressor,
    bs: BlobStore,
    conn,
    stats: StatCounter,
) -> int:
    """Ingest entries start..end; return how many entries the log returned.

    See ``_process_batch`` for the details.
    """
    n, _ = await _process_batch(
        src, start, end, mode=mode, ix=ix, sup=sup, bs=bs, conn=conn, stats=stats
    )
    return n


async def _process_batch(
    src: LogSource,
    start: int,
    end: int,
    *,
    mode: Literal["bootstrap", "live"],
    ix: FirstSeenIndex,
    sup: Suppressor,
    bs: BlobStore,
    conn,
    stats: StatCounter,
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
        _, bootstrap_done = await get_cursor(conn, log_id)
        emit = mode == "live" and bootstrap_done
        batch = StatCounter(entries=len(entries))
        rows: list[CandidateRow] = []
        new_certs: set[bytes] = set()
        new_fqdns: dict[str, tuple[int, int]] = {}  # NameRecord.key -> (ts_ms, index)
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
                if rec.key in new_fqdns or ix.get(rec.key) is not None:
                    continue
                new_fqdns[rec.key] = (parsed.timestamp_ms, index)
                batch.fqdns_new += 1
                reason = sup.reason(rec)
                if reason is not None:
                    batch.suppressed += 1
                    by_reason = f"supp_{reason}"
                    if hasattr(batch, by_reason):
                        setattr(batch, by_reason, getattr(batch, by_reason) + 1)
                elif emit:
                    rows.append(
                        CandidateRow(
                            rec.fqdn, rec.registrable, log_id, index, key,
                            parsed.timestamp_ms,
                        )
                    )
        batch.candidates = len(rows)
        last = entries[-1][0]
        if mode == "live":
            blob = bs.put(pack_entries(entries), RAW_MEDIA_TYPE)
            await add_raw_batch(conn, log_id, start, last, blob, len(entries), batch.bytes)
        await add_candidates(conn, rows)
        day = datetime.now(timezone.utc).date()
        await bump_stat(conn, log_id, day, mode, **batch.increments())
        await set_cursor(conn, log_id, last + 1, bootstrap_done)
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
    """Logs a log's entries/s (and lag or remaining) once per PROGRESS_INTERVAL_S."""

    def __init__(self, log: logging.Logger, what: str):
        self._log = log
        self._what = what
        self._t0 = time.monotonic()
        self._n = 0

    def note(self, n: int, next_index: int, size: int) -> None:
        self._n += n
        dt = time.monotonic() - self._t0
        if dt < PROGRESS_INTERVAL_S:
            return
        rate = self._n / dt if dt > 0 else 0.0
        label = "lag" if self._what == "tail" else "remaining"
        self._log.info(
            "%s %.1f entries/s %s=%d next_index=%d tree_size=%d",
            self._what, rate, label, size - next_index, next_index, size,
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


async def bootstrap_log(
    src: LogSource,
    cfg: Config,
    ix: FirstSeenIndex,
    sup: Suppressor,
    bs: BlobStore,
    conn,
    stop: asyncio.Event | None = None,
) -> bool:
    """Index the last ``bootstrap_days`` of the log, then mark it bootstrapped.

    Resumes from the cursor. Returns True once the log is bootstrapped, False
    if ``stop`` was set first (checked between batches).
    """
    log = _logger(src)
    next_index, done = await get_cursor(conn, src.info.log_id)
    await conn.rollback()  # end the read-only transaction get_cursor opened
    if done:
        return True
    now_ms = int(time.time() * 1000)
    since = await src.index_at(now_ms - cfg.bootstrap_days * 86_400_000)
    pos = max(next_index, since)
    size = await src.tree_size()
    log.info("bootstrap from %d to %d", pos, size)
    stats = StatCounter()
    progress = _Progress(log, "bootstrap")
    while pos < size:
        if stop is not None and stop.is_set():
            log.info("bootstrap stopped at %d of %d", pos, size)
            return False
        end = _batch_end(src, pos, size, cfg.batch_size)
        n, pos_next = await _process_batch(
            src, pos, end, mode="bootstrap", ix=ix, sup=sup, bs=bs, conn=conn, stats=stats
        )
        if n == 0:
            raise RuntimeError(f"log returned no entries for {pos}..{end}")
        pos = pos_next  # same value the batch wrote to the cursor
        progress.note(n, pos, size)
    try:
        await set_cursor(conn, src.info.log_id, pos, True)
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    log.info("bootstrap done at %d: %s", pos, stats.increments())
    return True


async def bootstrap_until_done(
    src: LogSource,
    cfg: Config,
    ix: FirstSeenIndex,
    sup: Suppressor,
    bs: BlobStore,
    db,
    stop: asyncio.Event,
) -> bool:
    """Run ``bootstrap_log`` until it completes or ``stop`` is set.

    Each failure is retried from the cursor after an exponential backoff
    (BOOTSTRAP_RETRY_BASE_S doubling, capped at BOOTSTRAP_RETRY_MAX_S), with
    no limit on attempts. ``db`` is a ``ConnPool`` or a connection.
    """
    failures = _Failures(_logger(src))
    delay = BOOTSTRAP_RETRY_BASE_S
    while not stop.is_set():
        try:
            async with _borrow(db) as conn:
                if await bootstrap_log(src, cfg, ix, sup, bs, conn, stop):
                    return True
        except Exception as e:
            failures.warn("bootstrap", e, delay)
            await _sleep_or_stop(stop, delay)
            delay = min(delay * 2, BOOTSTRAP_RETRY_MAX_S)
    return False


async def _tail_once(
    src: LogSource, cfg: Config, ix: FirstSeenIndex, sup: Suppressor, bs: BlobStore, conn
) -> tuple[int, int, int]:
    """One live batch from the cursor; return (entries, next index, tree size)."""
    next_index, _ = await get_cursor(conn, src.info.log_id)
    await conn.rollback()
    size = await src.tree_size()
    if next_index >= size:
        return 0, next_index, size
    end = _batch_end(src, next_index, size, cfg.batch_size)
    n, nxt = await _process_batch(
        src, next_index, end, mode="live", ix=ix, sup=sup, bs=bs, conn=conn,
        stats=StatCounter(),
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
    """
    log = _logger(src)
    progress = _Progress(log, "tail")
    failures = _Failures(log)
    while not stop.is_set():
        try:
            async with _borrow(db) as conn:
                n, next_index, size = await _tail_once(src, cfg, ix, sup, bs, conn)
            progress.note(n, next_index, size)
        except Exception as e:
            failures.warn("batch", e, IDLE_SLEEP_S)
            n = 0
        if n == 0:
            await _sleep_or_stop(stop, IDLE_SLEEP_S)


def _load_suppressor(cfg: Config) -> Suppressor:
    tranco = cfg.data_dir / "tranco.csv"
    if tranco.exists():
        return Suppressor.from_files(tranco, cfg.tranco_top_n, cfg.public_apexes)
    logging.getLogger(__name__).warning("%s missing; Tranco suppression disabled", tranco)
    # An empty file gives an empty Tranco set but keeps the public apexes.
    return Suppressor.from_files(Path(os.devnull), 0, cfg.public_apexes)


async def run(cfg: Config, mode: Literal["bootstrap", "tail"]) -> None:
    """Bootstrap or tail every active log, one task per log.

    The tasks share one HTTP client, one first-seen index and a ``ConnPool``
    of at most ``cfg.max_db_connections`` connections. SIGINT/SIGTERM set the
    stop event (bootstrap stops between batches, tail between batches); a
    second signal cancels the run.
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
            done = await bootstrapped_logs(conn) if mode == "tail" else set()
            await conn.rollback()
        finally:
            await conn.close()

        async with httpx.AsyncClient(
            timeout=60, headers={"User-Agent": USER_AGENT}
        ) as client:
            logs = await fetch_log_lists(cfg.log_lists, client)
            root.info("%d active logs", len(logs))
            if mode == "tail":
                skipped = [info for info in logs if info.log_id not in done]
                if skipped:
                    root.error(
                        "%d logs not bootstrapped; skipping (run bootstrap first): %s",
                        len(skipped),
                        "; ".join(f"{i.description} ({i.log_id})" for i in skipped),
                    )
                logs = [info for info in logs if info.log_id in done]
            with FirstSeenIndex(cfg.data_dir / "firstseen") as ix:

                async def one(info) -> None:
                    # Never raises: a failing log must not end gather() early,
                    # which would close the shared index and client under the
                    # sibling tasks still using them.
                    log = logging.getLogger(f"hakapik.ingest.{info.log_id}")
                    try:
                        src = make_source(info, client)
                        if mode == "bootstrap":
                            await bootstrap_until_done(src, cfg, ix, sup, bs, pool, stop)
                        else:
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
