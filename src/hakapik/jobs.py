"""The fetch queue: claim, advance, age out and enqueue fetch jobs.

All time comparisons use the database clock (now()). No function here
commits; the caller owns the transaction. Time comparisons use Postgres
now(), which is fixed per transaction, so callers keep claim/sweep
transactions short.
"""

from datetime import datetime

import psycopg

from hakapik.names import normalize
from hakapik.protocol import Job


class _LostRace(Exception):
    pass


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
            out.append((name, "already_open"))
            continue
        out.append((name, "queued"))
    return out


async def show_fqdn(conn: psycopg.AsyncConnection, fqdn: str) -> list[dict]:
    """Read-only history of an FQDN: candidates with jobs, attempts, latest manifest."""
    cur = await conn.execute(
        "SELECT id, reason, created_at FROM candidate WHERE fqdn = %s ORDER BY id",
        (fqdn,),
    )
    out = []
    for cid, reason, created_at in await cur.fetchall():
        cur = await conn.execute(
            """SELECT id, state, step, due_at FROM fetch_job
               WHERE candidate_id = %s ORDER BY id""",
            (cid,),
        )
        jobs = []
        for jid, state, step, due_at in await cur.fetchall():
            cur = await conn.execute(
                """SELECT step, started_at, outcome, http_status, final_url,
                          asn, asn_org
                   FROM attempt WHERE job_id = %s ORDER BY step""",
                (jid,),
            )
            attempts = [
                dict(zip(("step", "started_at", "outcome", "http_status",
                          "final_url", "asn", "asn_org"), r))
                for r in await cur.fetchall()
            ]
            jobs.append({"state": state, "step": step, "due_at": due_at,
                         "attempts": attempts})
        cur = await conn.execute(
            """SELECT version, sha256 FROM manifest
               WHERE candidate_id = %s ORDER BY version DESC LIMIT 1""",
            (cid,),
        )
        m = await cur.fetchone()
        out.append({"id": cid, "reason": reason, "created_at": created_at,
                    "jobs": jobs,
                    "manifest": {"version": m[0], "sha256": m[1]} if m else None})
    return out
