"""The fetch queue: claim, advance, age out and enqueue fetch jobs.

All time comparisons use the database clock (now()). No function here
commits; the caller owns the transaction.
"""

from datetime import datetime

import psycopg

from hakapik.db import CandidateRow, add_candidates
from hakapik.names import normalize
from hakapik.protocol import Job


async def claim_jobs(conn: psycopg.AsyncConnection, n: int, lease_s: int) -> list[Job]:
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
           RETURNING id, candidate_id, fqdn, registrable, step, priority, due_at""",
        (lease_s, n),
    )
    rows = sorted(await cur.fetchall(), key=lambda r: (-r[5], -r[6].timestamp()))
    return [Job(r[0], r[1], r[2], r[3], r[4], f"https://{r[2]}/") for r in rows]


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
             AND created_at < now() - make_interval(hours => %s)""",
        (ageout_hours,),
    )
    count = cur.rowcount
    if queue_cap is not None:
        cur = await conn.execute(
            """UPDATE fetch_job SET state = 'aged_out'
               WHERE id IN (
                 SELECT id FROM fetch_job
                 WHERE state = 'open' AND step = 0
                 ORDER BY priority ASC, created_at ASC
                 LIMIT (
                   SELECT greatest(count(*) - %s, 0) FROM fetch_job
                   WHERE state = 'open' AND step = 0)
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


async def enqueue_manual(
    conn: psycopg.AsyncConnection, names: list[str]
) -> list[tuple[str, str]]:
    """Queue names by hand: (input, queued | already_open | invalid | wildcard)."""
    out: list[tuple[str, str]] = []
    for name in names:
        rec = normalize(name)
        if rec.wildcard:
            out.append((name, "wildcard"))
            continue
        if not rec.valid:
            out.append((name, "invalid"))
            continue
        cur = await conn.execute(
            "SELECT 1 FROM fetch_job WHERE fqdn = %s AND state = 'open'", (rec.fqdn,)
        )
        if await cur.fetchone():
            out.append((name, "already_open"))
            continue
        await add_candidates(
            conn,
            [CandidateRow(rec.fqdn, rec.registrable, None, None, None, None, "manual")],
        )
        out.append((name, "queued"))
    return out
