import asyncio
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from conftest import _test_db_url

from hakapik.config import Config
from hakapik.db import CandidateRow, add_candidates, connect
from hakapik.jobs import (
    advance_job,
    attempts_today,
    claim_jobs,
    enqueue_manual,
    extend_lease,
    last_fetched,
    sweep,
)


LADDER = Config.retry_ladder_s  # the default; its last step is 86400 s


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
    claims = await claim_jobs(conn, 1, 60)
    assert [c.job.job_id for c in claims] == [newest]
    assert claims[0].job.url == "https://c.example.com/" and claims[0].job.step == 0
    cur = await conn.execute("SELECT claimed_until FROM fetch_job WHERE id = %s", (newest,))
    assert claims[0].claimed_until == (await cur.fetchone())[0]


async def test_claim_respects_due_and_lease(conn):
    future = await _add(conn, "a.example.com")
    await conn.execute("UPDATE fetch_job SET due_at = now() + interval '1 hour'")
    assert await claim_jobs(conn, 5, 60) == []
    await conn.execute("UPDATE fetch_job SET due_at = now()")
    assert [c.job.job_id for c in await claim_jobs(conn, 5, 60)] == [future]
    assert await claim_jobs(conn, 5, 60) == []


async def test_expired_lease_is_reclaimed(conn):
    jid = await _add(conn, "a.example.com")
    assert [c.job.job_id for c in await claim_jobs(conn, 1, 1)] == [jid]
    await conn.execute("UPDATE fetch_job SET claimed_until = now() - interval '1 second'")
    assert [c.job.job_id for c in await claim_jobs(conn, 1, 1)] == [jid]


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
    assert await sweep(conn, 1, 2, LADDER) == 3
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
    assert await sweep(conn, 1, None, LADDER) == 0
    assert (await _job(conn, leased))[1] == "open"
    # leased jobs do not count toward the cap either
    await _add(conn, "a.example.com", 20)
    await _add(conn, "b.example.com", 10)
    assert await sweep(conn, 1, 2, LADDER) == 0
    assert await sweep(conn, 1, 1, LADDER) == 1


async def test_advance_is_noop_on_closed_jobs(conn):
    aged = await _add(conn, "a.example.com", 7200)
    await sweep(conn, 1, None, LADDER)
    await advance_job(conn, aged, 0, (0, 120))
    assert (await _job(conn, aged))[:2] == (0, "aged_out")
    done = await _add(conn, "b.example.com")
    await advance_job(conn, done, 0, (0,))
    await advance_job(conn, done, 0, (0, 120))
    assert (await _job(conn, done))[:2] == (0, "done")


async def test_manual_lost_race_leaves_no_orphan(conn):
    # A real concurrent transaction: ``conn`` holds an uncommitted open job, so
    # the other enqueue's pre-check sees nothing and its insert waits on the
    # unique open-job index, then loses when ``conn`` commits.
    await conn.commit()
    assert await enqueue_manual(conn, ["race.example.com"]) == [("race.example.com", "queued")]
    other = await connect(_test_db_url())
    try:
        task = asyncio.create_task(enqueue_manual(other, ["race.example.com"]))
        for _ in range(200):
            cur = await conn.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                "AND datname = current_database()")
            if (await cur.fetchone())[0]:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("the second enqueue never waited on the first")
        assert not task.done()
        await conn.commit()
        assert await asyncio.wait_for(task, 10) == [("race.example.com", "already_open")]
        await other.commit()
    finally:
        await other.close()
    assert await _count(conn, "candidate") == 1
    assert await _count(conn, "fetch_job") == 1


async def test_claim_orders_by_priority_then_newest(conn):
    # Inserted in the reverse of the claim order, so neither the physical row
    # order nor RETURNING's order happens to match: the re-sort in claim_jobs
    # is what orders the list.
    ids = {}
    for fqdn, prio, age in [("lo-old.example.com", 0, 30), ("lo-new.example.com", 0, 10),
                            ("hi-old.example.com", 5, 40), ("hi-new.example.com", 5, 20)]:
        ids[fqdn] = await _add(conn, fqdn, age)
        await conn.execute("UPDATE fetch_job SET priority = %s WHERE id = %s",
                           (prio, ids[fqdn]))
    claims = await claim_jobs(conn, 4, 60)
    assert [c.job.fqdn for c in claims] == ["hi-new.example.com", "hi-old.example.com",
                                      "lo-new.example.com", "lo-old.example.com"]
    # The limit takes the highest priority first, not the newest.
    await conn.execute("UPDATE fetch_job SET claimed_until = NULL")
    assert [c.job.fqdn for c in await claim_jobs(conn, 1, 60)] == ["hi-new.example.com"]


async def test_sweep_takes_fractional_ageout_hours(conn):
    old = await _add(conn, "old.example.com", 2000)  # older than 0.5 h
    young = await _add(conn, "young.example.com", 1000)
    assert await sweep(conn, 0.5, None, LADDER) == 1
    assert (await _job(conn, old))[1] == "aged_out"
    assert (await _job(conn, young))[1] == "open"


async def test_extend_lease_only_for_the_holder_of_the_token(conn):
    jid = await _add(conn, "a.example.com")
    [claim] = await claim_jobs(conn, 1, 1)
    token = await extend_lease(conn, jid, 0, 600, claim.claimed_until)
    assert token is not None and token > claim.claimed_until
    cur = await conn.execute("SELECT claimed_until FROM fetch_job WHERE id = %s", (jid,))
    assert (await cur.fetchone())[0] == token
    # The old token no longer holds the lease; nor does a stale step.
    assert await extend_lease(conn, jid, 0, 600, claim.claimed_until) is None
    assert await extend_lease(conn, jid, 1, 600, token) is None
    await conn.execute("UPDATE fetch_job SET state = 'done' WHERE id = %s", (jid,))
    assert await extend_lease(conn, jid, 0, 600, token) is None  # closed


async def test_extend_lease_after_another_claim_is_a_noop(conn):
    jid = await _add(conn, "a.example.com")
    [old] = await claim_jobs(conn, 1, 1)
    await conn.execute(
        "UPDATE fetch_job SET claimed_until = now() - interval '1 second' WHERE id = %s",
        (jid,))
    await conn.commit()
    [new] = await claim_jobs(conn, 1, 60)  # a second holder after expiry
    assert await extend_lease(conn, jid, 0, 600, old.claimed_until) is None
    cur = await conn.execute("SELECT claimed_until FROM fetch_job WHERE id = %s", (jid,))
    assert (await cur.fetchone())[0] == new.claimed_until


async def test_extend_lease_after_the_result_was_stored_is_a_noop(conn):
    # store_result advances the job (advance_job) and commits; a heartbeat
    # tick that fires after that changes nothing.
    jid = await _add(conn, "a.example.com")
    [claim] = await claim_jobs(conn, 1, 60)
    await advance_job(conn, jid, 0, (0, 120))
    await conn.commit()
    assert await extend_lease(conn, jid, 0, 600, claim.claimed_until) is None
    assert (await _job(conn, jid))[:3] == (1, "open", None)


async def test_extend_lease_does_not_wait_for_a_locked_row(conn):
    jid = await _add(conn, "a.example.com")
    [claim] = await claim_jobs(conn, 1, 60)
    await conn.commit()
    other = await connect(_test_db_url())
    try:
        await other.execute("SELECT 1 FROM fetch_job WHERE id = %s FOR UPDATE", (jid,))
        t = asyncio.get_running_loop().time()
        with pytest.raises(psycopg.errors.LockNotAvailable):
            await extend_lease(conn, jid, 0, 600, claim.claimed_until)
        assert asyncio.get_running_loop().time() - t < 2
        await conn.rollback()
    finally:
        await other.close()


async def test_enqueue_manual_inserts_in_fqdn_order_and_reports_in_input_order(conn):
    # One global insert order (by fqdn, as add_candidates) rules out deadlocks
    # with a concurrent tail or enqueue; the output still follows the input.
    names = ["c.example.com", "*.x.com", "b.example.com", "bad..name", "a.example.com"]
    res = await enqueue_manual(conn, names)
    assert res == [("c.example.com", "queued"), ("*.x.com", "wildcard"),
                   ("b.example.com", "queued"), ("bad..name", "invalid"),
                   ("a.example.com", "queued")]
    cur = await conn.execute("SELECT fqdn FROM candidate ORDER BY id")
    assert [r[0] for r in await cur.fetchall()] == [
        "a.example.com", "b.example.com", "c.example.com"]
    cur = await conn.execute("SELECT fqdn FROM fetch_job ORDER BY id")
    assert [r[0] for r in await cur.fetchall()] == [
        "a.example.com", "b.example.com", "c.example.com"]


async def test_sweep_ages_out_retried_jobs_past_the_last_ladder_step(conn):
    # Beyond the last ladder step plus ageout_hours every open job goes, not
    # only untried ones; a leased job is still spared.
    ladder = (0, 120, 600, 3600)
    limit = ladder[-1] + 3600  # ageout_hours = 1
    stale = await _add(conn, "stale.example.com", limit + 60)
    young = await _add(conn, "young.example.com", limit - 60)
    leased = await _add(conn, "leased.example.com", limit + 60)
    await conn.execute("UPDATE fetch_job SET step = 3, due_at = now() + interval '1 hour'")
    await conn.execute(
        "UPDATE fetch_job SET claimed_until = now() + interval '10 minutes' WHERE id = %s",
        (leased,))
    assert await sweep(conn, 1, None, ladder) == 1
    assert (await _job(conn, stale))[1] == "aged_out"
    assert (await _job(conn, young))[1] == "open"
    assert (await _job(conn, leased))[1] == "open"
