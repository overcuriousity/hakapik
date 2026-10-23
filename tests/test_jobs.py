from datetime import datetime, timedelta, timezone

from hakapik.db import CandidateRow, add_candidates
from hakapik.jobs import (
    advance_job,
    attempts_today,
    claim_jobs,
    enqueue_manual,
    last_fetched,
    sweep,
)


def _row(fqdn):
    return CandidateRow(fqdn, "example.com", "log", 1, b"k", 1)


async def _count(conn, table, where="true"):
    cur = await conn.execute(f"SELECT count(*) FROM {table} WHERE {where}")
    return (await cur.fetchone())[0]


async def _add(conn, fqdn, age_s=0):
    """Add a candidate+job whose created_at/due_at are age_s seconds in the past."""
    await add_candidates(conn, [_row(fqdn)])
    cur = await conn.execute(
        """UPDATE fetch_job SET created_at = now() - make_interval(secs => %s),
             due_at = now() - make_interval(secs => %s)
           WHERE fqdn = %s AND state = 'open' RETURNING id""",
        (age_s, age_s, fqdn),
    )
    return (await cur.fetchone())[0]


async def test_one_open_job_per_fqdn(conn):
    await add_candidates(conn, [_row("a.example.com"), _row("a.example.com")])
    assert await enqueue_manual(conn, ["A.Example.com."]) == [("A.Example.com.", "already_open")]
    assert await _count(conn, "fetch_job") == 1
    assert await _count(conn, "candidate") == 2


async def test_claim_newest_first(conn):
    await _add(conn, "a.example.com", 30)
    await _add(conn, "b.example.com", 20)
    newest = await _add(conn, "c.example.com", 10)
    jobs = await claim_jobs(conn, 1, 60)
    assert [j.job_id for j in jobs] == [newest]
    assert jobs[0].url == "https://c.example.com/" and jobs[0].step == 0


async def test_claim_respects_due_and_lease(conn):
    future = await _add(conn, "a.example.com")
    await conn.execute("UPDATE fetch_job SET due_at = now() + interval '1 hour'")
    assert await claim_jobs(conn, 5, 60) == []
    await conn.execute("UPDATE fetch_job SET due_at = now()")
    assert [j.job_id for j in await claim_jobs(conn, 5, 60)] == [future]
    assert await claim_jobs(conn, 5, 60) == []


async def test_expired_lease_is_reclaimed(conn):
    jid = await _add(conn, "a.example.com")
    assert [j.job_id for j in await claim_jobs(conn, 1, 1)] == [jid]
    await conn.execute("UPDATE fetch_job SET claimed_until = now() - interval '1 second'")
    assert [j.job_id for j in await claim_jobs(conn, 1, 1)] == [jid]


async def _job(conn, jid):
    cur = await conn.execute(
        "SELECT step, state, claimed_until, due_at - created_at FROM fetch_job WHERE id = %s",
        (jid,),
    )
    return await cur.fetchone()


async def test_advance_walks_the_ladder(conn):
    ladder = (0, 120, 600)
    jid = await _add(conn, "a.example.com")
    await claim_jobs(conn, 1, 60)
    await advance_job(conn, jid, 0, ladder)
    step, state, claimed, offset = await _job(conn, jid)
    assert (step, state, claimed, offset) == (1, "open", None, timedelta(seconds=120))
    await advance_job(conn, jid, 0, ladder)  # stale step: no-op
    assert (await _job(conn, jid))[0] == 1
    await advance_job(conn, jid, 1, ladder)
    assert (await _job(conn, jid))[3] == timedelta(seconds=600)
    await advance_job(conn, jid, 2, ladder)
    assert (await _job(conn, jid))[:2] == (2, "done")


async def test_sweep_ages_out_old_and_excess(conn):
    old = await _add(conn, "old.example.com", 7200)
    retry = await _add(conn, "retry.example.com", 7200)
    await conn.execute("UPDATE fetch_job SET step = 1 WHERE id = %s", (retry,))
    fresh = [await _add(conn, f"f{i}.example.com", 40 - i) for i in range(4)]
    assert await sweep(conn, 1, 2) == 3
    states = {
        r[0]: r[1] for r in await (await conn.execute("SELECT id, state FROM fetch_job")).fetchall()
    }
    assert states[old] == "aged_out" and states[retry] == "open"
    assert [states[i] for i in fresh] == ["aged_out", "aged_out", "open", "open"]


async def test_enqueue_manual_rejects(conn):
    res = await enqueue_manual(conn, ["*.x.com", "bad..name", "ok.example.org"])
    assert [s for _, s in res] == ["wildcard", "invalid", "queued"]
    cur = await conn.execute("SELECT reason, log_id FROM candidate")
    assert await cur.fetchall() == [("manual", None)]
    assert await _count(conn, "fetch_job") == 1


async def test_last_fetched_and_attempts_today(conn):
    jid = await _add(conn, "a.example.com")
    await _add(conn, "b.example.com")
    await conn.execute("INSERT INTO node (node_id, public_key) VALUES ('n', 'k')")
    await conn.execute("INSERT INTO blob (sha256, size, media_type) VALUES ('s', 1, 'x')")
    await conn.execute(
        """INSERT INTO attempt (job_id, step, node_id, started_at, finished_at, outcome, envelope_sha256)
           VALUES (%s, 0, 'n', now() - interval '2 days', now() - interval '2 days', 'live', 's'),
                  (%s, 1, 'n', now(), now(), 'live', 's')""",
        (jid, jid),
    )
    got = await last_fetched(conn, ["a.example.com", "b.example.com"])
    assert list(got) == ["a.example.com"]
    assert isinstance(got["a.example.com"], datetime)
    assert abs(datetime.now(timezone.utc) - got["a.example.com"]) < timedelta(minutes=1)
    assert await attempts_today(conn) == 1


async def test_sweep_spares_leased_jobs(conn):
    leased = await _add(conn, "leased.example.com", 7200)
    await claim_jobs(conn, 1, 600)
    assert await sweep(conn, 1, None) == 0
    assert (await _job(conn, leased))[1] == "open"
    # leased jobs do not count toward the cap either
    await _add(conn, "a.example.com", 20)
    await _add(conn, "b.example.com", 10)
    assert await sweep(conn, 1, 2) == 0
    assert await sweep(conn, 1, 1) == 1


async def test_advance_is_noop_on_closed_jobs(conn):
    aged = await _add(conn, "a.example.com", 7200)
    await sweep(conn, 1, None)
    await advance_job(conn, aged, 0, (0, 120))
    assert (await _job(conn, aged))[:2] == (0, "aged_out")
    done = await _add(conn, "b.example.com")
    await advance_job(conn, done, 0, (0,))
    await advance_job(conn, done, 0, (0, 120))
    assert (await _job(conn, done))[:2] == (0, "done")


async def test_manual_lost_race_leaves_no_orphan(conn, monkeypatch):
    # Simulate by making the pre-check blind: open job exists but SELECT says no.
    await _add(conn, "race.example.com")
    orig = conn.execute

    async def blind(sql, *a, **k):
        if sql.startswith("SELECT 1 FROM fetch_job"):
            return await orig("SELECT 1 WHERE false")
        return await orig(sql, *a, **k)

    monkeypatch.setattr(conn, "execute", blind, raising=False)
    assert await enqueue_manual(conn, ["race.example.com"]) == [("race.example.com", "already_open")]
    monkeypatch.undo()
    assert await _count(conn, "candidate") == 1
    assert await _count(conn, "fetch_job") == 1
