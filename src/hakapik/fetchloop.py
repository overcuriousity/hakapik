"""The head's fetch scheduler, running the head's own worker role in-process.

Each iteration sweeps the queue, checks the optional daily cap, leases due
jobs up to the free worker slots and runs each as its own task:
``run_job`` -> ``store_result`` in a borrowed connection -> commit. The claim
and sweep transactions are committed at once (jobs use the transaction's
fixed now()). While ``run_job`` runs, a heartbeat extends its job's lease
every lease_s / 3, so a running job is never claimed again; it ends when
``run_job`` returns, before the store. ``job_timeout_s`` bounds the run. A task that fails or times out leaves its job leased; it is claimed
again after the lease expires. Signal handling belongs to the caller: setting
``stop`` ends claiming, and running tasks finish before ``run_fetch`` returns.
"""

import asyncio
import contextlib
import hashlib
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

import maxminddb

from hakapik.asn import MMDB_MEDIA_TYPE, AsnDb
from hakapik.blobstore import BlobStore
from hakapik.browser import Browser
from hakapik.config import Config
from hakapik.db import connect, lock_blob, migrate
from hakapik.ingest import ConnPool
from hakapik.jobs import Claim, attempts_today, claim_jobs, extend_lease, sweep
from hakapik.protocol import NodeKey, open_envelope
from hakapik.resolve import Resolver
from hakapik.store import ResultRejected, register_node, store_result
from hakapik.worker import BrowserLike, IpSpacer, ResolverLike, run_job

log = logging.getLogger(__name__)

IDLE_SLEEP_S = 2.0  # nothing claimed
CAP_SLEEP_S = 60.0  # daily cap reached


async def _load_asn(cfg: Config, bs: BlobStore, conn) -> AsnDb | None:
    """Load the snapshot and commit its blob row, so it is always referenced.

    The blob lock is held from before the put until that commit: the orphan
    sweep cannot unlink an existing snapshot file this load relies on.
    """
    if cfg.asn_mmdb is None:
        return None
    try:
        data = Path(cfg.asn_mmdb).read_bytes()
        await lock_blob(conn, hashlib.sha256(data).hexdigest())
        asn = AsnDb.from_bytes(data, bs, cfg.asn_mmdb)
    except (OSError, ValueError, maxminddb.InvalidDatabaseError) as e:
        await conn.rollback()
        log.warning("ASN database %s unusable (%r); ASN enrichment disabled",
                    cfg.asn_mmdb, e)
        return None
    await conn.execute(
        "INSERT INTO blob (sha256, size, media_type) VALUES (%s, %s, %s) "
        "ON CONFLICT DO NOTHING",
        (asn.sha256, asn.size, MMDB_MEDIA_TYPE),
    )
    await conn.commit()
    return asn


async def _heartbeat(pool: ConnPool, claim: Claim, lease_s: int) -> None:
    """Extend the claim's lease every lease_s / 3 until cancelled or the claim is lost.

    Each extension is guarded by the token it last wrote, so it never extends
    another holder's claim. A failed extension is logged and tried again at
    the next tick; it does not end the job. The job task cancels the
    heartbeat as soon as run_job returns, before the store, so a tick never
    meets the job's own store_result.
    """
    job, token = claim
    while True:
        await asyncio.sleep(max(lease_s / 3, 0.05))
        try:
            async with pool.borrow() as c:
                new = await extend_lease(c, job.job_id, job.step, lease_s, token)
                await c.commit()
        except Exception:
            log.warning("job %d %s: lease extension failed; retrying next tick",
                        job.job_id, job.fqdn, exc_info=True)
            continue
        if new is None:
            # store_result's stale check decides what becomes of the result.
            log.warning("job %d %s: lease lost to another claim; heartbeat stops",
                        job.job_id, job.fqdn)
            return
        token = new


async def _sleep_or_stop(stop: asyncio.Event, seconds: float) -> None:
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), seconds)


async def run_fetch(cfg: Config, *, stop: asyncio.Event,
                    resolver: ResolverLike | None = None,
                    browser: BrowserLike | None = None, once: bool = False) -> None:
    """Fetch due jobs until ``stop`` is set (or one iteration with ``once``).

    An injected ``browser`` is used as is; the default ``Browser`` is opened
    and closed here, as is the ASN database.
    """
    bs = BlobStore(cfg.data_dir / "blobs")
    # In a thread: creating the key writes and fsyncs files (blocking I/O).
    key = await asyncio.to_thread(NodeKey.load_or_create, cfg.data_dir / "node.key")
    conn = await connect(cfg.database_url)
    try:
        await migrate(conn)
        await register_node(conn, key.node_id, key.public_key)
        await conn.commit()
        asn_db = await _load_asn(cfg, bs, conn)
    finally:
        await conn.close()
    pool = ConnPool(cfg.database_url, min(cfg.max_db_connections, cfg.fetch_workers + 2))
    try:
        if resolver is None:
            resolver = Resolver(cfg.resolver_nameservers,
                                query_deadline_s=cfg.resolver_query_deadline_s)
        async with contextlib.AsyncExitStack() as stack:
            if browser is None:
                browser = await stack.enter_async_context(
                    Browser(proxy=cfg.fetch_proxy, nav_timeout_s=cfg.nav_timeout_s))
            spacer = IpSpacer(cfg.fetch_per_ip_interval_s)

            async def one(claim: Claim) -> None:
                # Never raises: a failed job stays leased until its lease expires.
                job = claim.job
                log.info("claimed job %d %s step %d", job.job_id, job.fqdn, job.step)
                beat = asyncio.create_task(_heartbeat(pool, claim, cfg.lease_s))

                async def end_beat() -> None:
                    beat.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await beat

                try:
                    bound = asyncio.timeout(cfg.job_timeout_s)
                    try:
                        async with bound:
                            env = await run_job(
                                job, resolver=resolver, browser=browser, bs=bs, key=key,
                                egress_address=cfg.egress_address, spacer=spacer)
                    except TimeoutError:
                        if not bound.expired():
                            raise  # raised inside run_job: a plain task failure
                        # Nothing is stored; the lease expires and the job is retried.
                        log.error("job %d %s timed out after %s s; nothing stored",
                                  job.job_id, job.fqdn, cfg.job_timeout_s)
                        return
                    # The lease has at least 2/3 of lease_s left (the last tick
                    # was under lease_s / 3 ago) and the store takes seconds, so
                    # the heartbeat ends here, before store_result locks the row.
                    await end_beat()
                    # Read before storing: after the commit only the log line
                    # runs, so a job logged as failed below was never stored.
                    outcome = open_envelope(env, {key.node_id: key.public_key}.get).outcome
                    async with pool.borrow() as c:
                        try:
                            attempt_id = await store_result(
                                c, bs, env, cfg.retry_ladder_s, asn_db=asn_db)
                            await c.commit()
                        except ResultRejected as e:
                            await c.rollback()
                            log.error("job %d %s: result rejected: %s",
                                      job.job_id, job.fqdn, e)
                            return
                    log.info("finished job %d %s outcome %s attempt %s", job.job_id,
                             job.fqdn, outcome,
                             "duplicate" if attempt_id is None else attempt_id)
                except Exception:
                    log.exception("job %d %s failed", job.job_id, job.fqdn)
                finally:
                    await end_beat()

            await _loop(cfg, stop, once, pool, one)
    finally:
        await pool.close()
        if asn_db is not None:
            asn_db.close()


async def _loop(cfg: Config, stop: asyncio.Event, once: bool, pool: ConnPool,
                one: Callable[[Claim], Awaitable[None]]) -> None:
    running: set[asyncio.Task] = set()
    try:
        while not stop.is_set():
            jobs: list[Claim] = []
            capped = False
            # The sweep has its own try: a failing sweep must not stop claims.
            try:
                async with pool.borrow() as conn:
                    aged = await sweep(conn, cfg.ageout_hours, cfg.queue_cap,
                                       cfg.retry_ladder_s)
                    await conn.commit()
                if aged:
                    log.info("aged out %d jobs", aged)
            except Exception:
                log.exception("fetch queue sweep failed")
            try:
                async with pool.borrow() as conn:
                    free = cfg.fetch_workers - len(running)
                    if cfg.fetch_daily_cap is not None:
                        # Tasks in flight have not stored their attempt yet.
                        used = await attempts_today(conn) + len(running)
                        await conn.rollback()
                        capped = used >= cfg.fetch_daily_cap
                        free = min(free, cfg.fetch_daily_cap - used)
                    if free > 0:
                        jobs = await claim_jobs(conn, free, cfg.lease_s)
                        await conn.commit()
            except Exception:
                log.exception("fetch iteration failed")
            for job in jobs:
                task = asyncio.create_task(one(job))
                running.add(task)
                task.add_done_callback(running.discard)
            if once:
                break
            if capped:
                await _sleep_or_stop(stop, CAP_SLEEP_S)
            elif not jobs:
                await _sleep_or_stop(stop, IDLE_SLEEP_S)
    except BaseException:
        for task in running:
            task.cancel()
        await asyncio.gather(*running, return_exceptions=True)
        raise
    if stop.is_set() and running:
        log.info("stopping; %d running job(s) finish first (Ctrl-C again aborts)",
                 len(running))
    await asyncio.gather(*running)
