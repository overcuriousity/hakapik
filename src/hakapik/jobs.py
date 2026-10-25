"""The fetch queue: claim, advance, age out and enqueue fetch jobs.

All time comparisons use the database clock (now()). No function here
commits; the caller owns the transaction. Time comparisons use Postgres
now(), which is fixed per transaction, so callers keep claim/sweep
transactions short.
"""

from datetime import datetime
from typing import NamedTuple

import psycopg

from hakapik.names import NameRecord, normalize
from hakapik.protocol import Job


class _LostRace(Exception):
    pass


class Claim(NamedTuple):
    """A leased job and the claimed_until this claim set: the claim's token.

    The token stays out of ``Job``, which is the worker protocol's wire type.
    """

    job: Job
    claimed_until: datetime


async def claim_jobs(conn: psycopg.AsyncConnection, n: int, lease_s: int) -> list[Claim]:
    """Lease up to ``n`` due open jobs, highest priority and newest first."""
    cur = await conn.execute(
        """UPDATE fetch_job SET claimed_until = now() + make_interval(secs => %s)
           WHERE id IN (
             SELECT id FROM fetch_job
             WHERE state = 'open' AND due_at <= now()
               AND (claimed_until IS NULL OR claimed_until <= now())
             ORDER BY priority DESC, due_at DESC
             LIMIT %s
             FOR UPDATE SKIP LOCKED)
           RETURNING id, candidate_id, fqdn, registrable, step, priority, due_at,
                     claimed_until""",
        (lease_s, n),
    )
    rows = sorted(await cur.fetchall(), key=lambda r: (-r[5], -r[6].timestamp()))
    return [Claim(Job(r[0], r[1], r[2], r[3], r[4], f"https://{r[2]}/"), r[7])
            for r in rows]


LEASE_LOCK_TIMEOUT = "100ms"  # how long extend_lease waits for the job row


async def extend_lease(
    conn: psycopg.AsyncConnection, job_id: int, step: int, lease_s: int,
    claimed_until: datetime,
) -> datetime | None:
    """Push a held lease to now() + lease_s; the new token, or None if not held.

    The lease is held while the job is open at ``step`` and its claimed_until
    is still ``claimed_until`` (the token this holder last wrote). None means
    the claim was lost (re-claimed after expiry) or the job moved on.

    Sets lock_timeout for the caller's transaction: if the row is locked
    (e.g. by this job's own store_result), this raises
    psycopg.errors.LockNotAvailable after LEASE_LOCK_TIMEOUT instead of
    waiting; the caller rolls back and tries again later.
    """
    await conn.execute(f"SET LOCAL lock_timeout = '{LEASE_LOCK_TIMEOUT}'")
    cur = await conn.execute(
        """UPDATE fetch_job SET claimed_until = now() + make_interval(secs => %s)
           WHERE id = %s AND state = 'open' AND step = %s AND claimed_until = %s
           RETURNING claimed_until""",
        (lease_s, job_id, step, claimed_until),
    )
    row = await cur.fetchone()
    return None if row is None else row[0]


async def advance_job(
    conn: psycopg.AsyncConnection, job_id: int, step: int, ladder: tuple[int, ...]
) -> None:
    """Move a job past ``step``; a no-op if the job is no longer at that step."""
    if step + 1 < len(ladder):
        await conn.execute(
            """UPDATE fetch_job SET step = %s, claimed_until = NULL,
                 due_at = created_at + make_interval(secs => %s)
               WHERE id = %s AND step = %s AND state = 'open'""",
            (step + 1, ladder[step + 1], job_id, step),
        )
    else:
        await conn.execute(
            """UPDATE fetch_job SET state = 'done', claimed_until = NULL
               WHERE id = %s AND step = %s AND state = 'open'""",
            (job_id, step),
        )


async def sweep(
    conn: psycopg.AsyncConnection, ageout_hours: float, queue_cap: int | None
) -> int:
    """Age out stale untried jobs, then the lowest-ranked excess over the cap."""
    cur = await conn.execute(
        """UPDATE fetch_job SET state = 'aged_out'
           WHERE state = 'open' AND step = 0
             AND (claimed_until IS NULL OR claimed_until <= now())
             AND created_at < now() - make_interval(secs => %s * 3600)""",
        (ageout_hours,),
    )
    count = cur.rowcount
    if queue_cap is not None:
        cur = await conn.execute(
            """UPDATE fetch_job SET state = 'aged_out'
               WHERE id IN (
                 SELECT id FROM fetch_job
                 WHERE state = 'open' AND step = 0
                   AND (claimed_until IS NULL OR claimed_until <= now())
                 ORDER BY priority ASC, created_at ASC, id ASC
                 LIMIT (
                   SELECT greatest(count(*) - %s, 0) FROM fetch_job
                   WHERE state = 'open' AND step = 0
                     AND (claimed_until IS NULL OR claimed_until <= now()))
                 )""",
            (queue_cap,),
        )
        count += cur.rowcount
    return count


async def attempts_today(conn: psycopg.AsyncConnection) -> int:
    """Attempts started since 00:00 UTC today."""
    cur = await conn.execute(
        """SELECT count(*) FROM attempt
           WHERE started_at >= date_trunc('day', now() AT TIME ZONE 'UTC')
                               AT TIME ZONE 'UTC'"""
    )
    return (await cur.fetchone())[0]


async def last_fetched(
    conn: psycopg.AsyncConnection, fqdns: list[str]
) -> dict[str, datetime]:
    """Latest attempt finish time per FQDN; FQDNs never fetched are absent."""
    cur = await conn.execute(
        """SELECT j.fqdn, max(a.finished_at) FROM attempt a
           JOIN fetch_job j ON j.id = a.job_id
           WHERE j.fqdn = ANY(%s) GROUP BY j.fqdn""",
        (fqdns,),
    )
    return dict(await cur.fetchall())


async def open_job_fqdns(conn: psycopg.AsyncConnection, fqdns: list[str]) -> set[str]:
    """The FQDNs among ``fqdns`` that have an open fetch job."""
    cur = await conn.execute(
        "SELECT fqdn FROM fetch_job WHERE state = 'open' AND fqdn = ANY(%s)", (fqdns,)
    )
    return {r[0] for r in await cur.fetchall()}


async def enqueue_manual(
    conn: psycopg.AsyncConnection, names: list[str]
) -> list[tuple[str, str]]:
    """Queue names by hand: (input, queued | already_open | invalid | wildcard).

    Results come back in input order.
    """
    status: dict[int, str] = {}
    valid = []
    for i, name in enumerate(names):
        rec = normalize(name)
        if rec.wildcard:
            status[i] = "wildcard"
        elif not rec.valid:
            status[i] = "invalid"
        else:
            valid.append((i, rec))
    # Insert in one global order by fqdn, as db.add_candidates does: a
    # concurrent tail or enqueue waits on the same unique open-job index, and
    # one order for everyone rules out deadlocks.
    for i, rec in sorted(valid, key=lambda v: v[1].fqdn):
        status[i] = await _enqueue_one(conn, rec)
    return [(name, status[i]) for i, name in enumerate(names)]


async def _enqueue_one(conn: psycopg.AsyncConnection, rec: NameRecord) -> str:
    cur = await conn.execute(
        "SELECT 1 FROM fetch_job WHERE fqdn = %s AND state = 'open'", (rec.fqdn,)
    )
    if await cur.fetchone():
        return "already_open"
    # The SELECT above is only a fast path. A concurrent enqueue can still win
    # the unique open-job index, so the job insert reports whether it created a
    # row; if not, the savepoint rolls the candidate back (no orphan).
    try:
        async with conn.transaction():
            cur = await conn.execute(
                """INSERT INTO candidate (fqdn, registrable, reason)
                   VALUES (%s, %s, 'manual') RETURNING id""",
                (rec.fqdn, rec.registrable),
            )
            cid = (await cur.fetchone())[0]
            cur = await conn.execute(
                """INSERT INTO fetch_job (candidate_id, fqdn, registrable, due_at)
                   VALUES (%s, %s, %s, now())
                   ON CONFLICT (fqdn) WHERE state = 'open' DO NOTHING
                   RETURNING id""",
                (cid, rec.fqdn, rec.registrable),
            )
            if await cur.fetchone() is None:
                raise _LostRace
    except _LostRace:
        return "already_open"
    return "queued"


async def show_fqdn(conn: psycopg.AsyncConnection, fqdn: str) -> list[dict]:
    """Read-only history of an FQDN: candidates with jobs, attempts, latest manifest.

    Four queries whatever the history's length (one per table).
    """
    cur = await conn.execute(
        "SELECT id, reason, created_at FROM candidate WHERE fqdn = %s ORDER BY id",
        (fqdn,),
    )
    cands = await cur.fetchall()
    cids = [c[0] for c in cands]
    cur = await conn.execute(
        """SELECT id, candidate_id, state, step, due_at FROM fetch_job
           WHERE candidate_id = ANY(%s) ORDER BY id""",
        (cids,),
    )
    jobs = await cur.fetchall()
    cur = await conn.execute(
        """SELECT job_id, step, started_at, outcome, http_status, final_url,
                  asn, asn_org
           FROM attempt WHERE job_id = ANY(%s) ORDER BY job_id, step""",
        ([j[0] for j in jobs],),
    )
    attempts: dict[int, list[dict]] = {}
    for jid, *rest in await cur.fetchall():
        attempts.setdefault(jid, []).append(
            dict(zip(("step", "started_at", "outcome", "http_status",
                      "final_url", "asn", "asn_org"), rest))
        )
    cur = await conn.execute(
        """SELECT DISTINCT ON (candidate_id) candidate_id, version, sha256
           FROM manifest WHERE candidate_id = ANY(%s)
           ORDER BY candidate_id, version DESC""",
        (cids,),
    )
    manifests = {r[0]: {"version": r[1], "sha256": r[2]} for r in await cur.fetchall()}
    by_cand: dict[int, list[dict]] = {}
    for jid, cid, state, step, due_at in jobs:
        by_cand.setdefault(cid, []).append(
            {"state": state, "step": step, "due_at": due_at,
             "attempts": attempts.get(jid, [])}
        )
    return [
        {"id": cid, "reason": reason, "created_at": created_at,
         "jobs": by_cand.get(cid, []), "manifest": manifests.get(cid)}
        for cid, reason, created_at in cands
    ]
