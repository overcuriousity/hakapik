"""The head's fetch scheduler, running the head's own worker role in-process.

Each iteration sweeps the queue, checks the optional daily cap, leases due
jobs up to the free worker slots and runs each as its own task:
``run_job`` -> ``store_result`` in a borrowed connection -> commit. The claim
and sweep transactions are committed at once (jobs use the transaction's
fixed now()). A task that fails leaves its job leased; it is claimed again
after the lease expires. Signal handling belongs to the caller: setting
``stop`` ends claiming, and running tasks finish before ``run_fetch`` returns.
"""

import asyncio
import contextlib
import logging

import maxminddb

from hakapik.asn import AsnDb
from hakapik.blobstore import BlobStore
from hakapik.browser import Browser
from hakapik.config import Config
from hakapik.db import connect, migrate
from hakapik.ingest import ConnPool
from hakapik.jobs import attempts_today, claim_jobs, sweep
from hakapik.protocol import Job, NodeKey, open_envelope
from hakapik.resolve import Resolver
from hakapik.store import ResultRejected, register_node, store_result
from hakapik.worker import IpSpacer, run_job

log = logging.getLogger(__name__)

IDLE_SLEEP_S = 2.0  # nothing claimed
CAP_SLEEP_S = 60.0  # daily cap reached


def _load_asn(cfg: Config, bs: BlobStore) -> AsnDb | None:
    if cfg.asn_mmdb is None:
        return None
    try:
        return AsnDb.load(cfg.asn_mmdb, bs)
    except (OSError, ValueError, maxminddb.InvalidDatabaseError) as e:
        log.warning("ASN database %s unusable (%r); ASN enrichment disabled",
                    cfg.asn_mmdb, e)
        return None


async def _sleep_or_stop(stop: asyncio.Event, seconds: float) -> None:
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), seconds)


async def run_fetch(cfg: Config, *, stop: asyncio.Event, resolver=None, browser=None,
                    once: bool = False) -> None:
    """Fetch due jobs until ``stop`` is set (or one iteration with ``once``).

    An injected ``browser`` is used as is; the default ``Browser`` is opened
    and closed here.
    """
    bs = BlobStore(cfg.data_dir / "blobs")
    key = NodeKey.load_or_create(cfg.data_dir / "node.key")
    conn = await connect(cfg.database_url)
    try:
        await migrate(conn)
        await register_node(conn, key.node_id, key.public_key)
        await conn.commit()
    finally:
        await conn.close()
    asn_db = _load_asn(cfg, bs)
    if resolver is None:
        resolver = Resolver(cfg.resolver_nameservers)
    pool = ConnPool(cfg.database_url, min(cfg.max_db_connections, cfg.fetch_workers + 2))
    try:
        async with contextlib.AsyncExitStack() as stack:
            if browser is None:
                browser = await stack.enter_async_context(
                    Browser(proxy=cfg.fetch_proxy, nav_timeout_s=cfg.nav_timeout_s))
            spacer = IpSpacer(cfg.fetch_per_ip_interval_s)

            async def one(job: Job) -> None:
                # Never raises: a failed job stays leased until its lease expires.
                log.info("claimed job %d %s step %d", job.job_id, job.fqdn, job.step)
                try:
                    env = await run_job(job, resolver=resolver, browser=browser, bs=bs,
                                        key=key, egress_address=cfg.egress_address,
                                        spacer=spacer)
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
                    outcome = open_envelope(env, {key.node_id: key.public_key}.get).outcome
                    log.info("finished job %d %s outcome %s attempt %s", job.job_id,
                             job.fqdn, outcome,
                             "duplicate" if attempt_id is None else attempt_id)
                except Exception:
                    log.exception("job %d %s failed", job.job_id, job.fqdn)

            await _loop(cfg, stop, once, pool, one)
    finally:
        await pool.close()


async def _loop(cfg: Config, stop: asyncio.Event, once: bool, pool: ConnPool,
                one) -> None:
    running: set[asyncio.Task] = set()
    try:
        while not stop.is_set():
            jobs: list[Job] = []
            capped = False
            try:
                async with pool.borrow() as conn:
                    aged = await sweep(conn, cfg.ageout_hours, cfg.queue_cap)
                    await conn.commit()
                    if aged:
                        log.info("aged out %d jobs", aged)
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
    await asyncio.gather(*running)
