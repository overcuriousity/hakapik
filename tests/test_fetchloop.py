import asyncio
import hashlib
import logging
import threading

import pytest
from conftest import _test_db_url
from test_worker import T, FakeBrowser

from hakapik import fetchloop
from hakapik.asn import AsnDb
from hakapik.config import Config
from hakapik.fetchloop import run_fetch
from hakapik.db import connect
from hakapik.jobs import claim_jobs, enqueue_manual
from hakapik.protocol import DnsAnswer, NodeKey
from hakapik.store import ResultRejected


class FakeResolver:
    async def resolve(self, fqdn, registrable):
        return (DnsAnswer(fqdn, "A", "NOERROR", 60, ("192.0.2.1",), "fake", T),)


def _cfg(tmp_path, **kw):
    return Config(data_dir=tmp_path, database_url=_test_db_url(), **kw)


async def _count(conn, table, where="true"):
    cur = await conn.execute(f"SELECT count(*) FROM {table} WHERE {where}")
    n = (await cur.fetchone())[0]
    await conn.rollback()
    return n


async def _queue(conn, *names):
    await enqueue_manual(conn, list(names))
    await conn.commit()


async def _once(cfg, **kw):
    await run_fetch(cfg, stop=asyncio.Event(), resolver=FakeResolver(),
                    browser=kw.pop("browser", FakeBrowser()), once=True, **kw)


async def test_enqueue_then_fetch_once_end_to_end(conn, tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="hakapik.fetchloop")
    cfg = _cfg(tmp_path, fetch_workers=2)
    await _queue(conn, "a.example.com", "b.example.com")
    await _once(cfg)
    assert await _count(conn, "attempt") == 2
    assert await _count(conn, "attempt", "outcome = 'live'") == 2
    assert await _count(conn, "fetch_job", "step = 1 AND claimed_until IS NULL") == 2
    assert await _count(conn, "manifest") == 2
    key = NodeKey.load_or_create(tmp_path / "node.key")
    cur = await conn.execute("SELECT node_id, public_key FROM node")
    assert [(r[0], bytes(r[1])) for r in await cur.fetchall()] == [
        (key.node_id, key.public_key)]
    await conn.rollback()
    text = caplog.text
    assert "a.example.com" in text and "b.example.com" in text
    assert text.count("claimed job") == 2 and text.count("finished job") == 2
    assert "outcome live" in text


async def test_claims_no_more_than_free_workers(conn, tmp_path):
    cfg = _cfg(tmp_path, fetch_workers=1)
    await _queue(conn, "a.example.com", "b.example.com")
    await _once(cfg)
    assert await _count(conn, "attempt") == 1
    assert await _count(conn, "fetch_job", "step = 0 AND claimed_until IS NULL") == 1


async def test_daily_cap_blocks_claims(conn, tmp_path):
    cfg = _cfg(tmp_path, fetch_daily_cap=0)
    await _queue(conn, "a.example.com")
    await _once(cfg)
    assert await _count(conn, "attempt") == 0
    assert await _count(conn, "fetch_job", "claimed_until IS NOT NULL") == 0


async def test_daily_cap_limits_claims_to_remaining(conn, tmp_path):
    cfg = _cfg(tmp_path, fetch_workers=4, fetch_daily_cap=1)
    await _queue(conn, "a.example.com", "b.example.com", "c.example.com")
    await _once(cfg)
    assert await _count(conn, "attempt") == 1
    await _once(cfg)
    assert await _count(conn, "attempt") == 1


async def test_daily_cap_counts_tasks_in_flight(conn, tmp_path, monkeypatch):
    monkeypatch.setattr(fetchloop, "IDLE_SLEEP_S", 0.01)
    monkeypatch.setattr(fetchloop, "CAP_SLEEP_S", 0.01)
    gate = asyncio.Event()
    started = []

    class SlowBrowser(FakeBrowser):
        async def capture(self, url, profile, *, click_through=False):
            started.append(url)
            await gate.wait()
            return await super().capture(url, profile, click_through=click_through)

    cfg = _cfg(tmp_path, fetch_workers=4, fetch_daily_cap=1)
    await _queue(conn, "a.example.com", "b.example.com")
    stop = asyncio.Event()
    task = asyncio.create_task(run_fetch(
        cfg, stop=stop, resolver=FakeResolver(), browser=SlowBrowser()))
    for _ in range(200):
        if started:
            break
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.1)  # several loop iterations with one task in flight
    assert await _count(conn, "fetch_job", "claimed_until IS NOT NULL") == 1
    stop.set()
    gate.set()
    await asyncio.wait_for(task, 10)
    assert await _count(conn, "attempt") == 1


async def test_stop_set_claims_nothing(conn, tmp_path):
    cfg = _cfg(tmp_path)
    await _queue(conn, "a.example.com")
    stop = asyncio.Event()
    stop.set()
    await run_fetch(cfg, stop=stop, resolver=FakeResolver(), browser=FakeBrowser())
    assert await _count(conn, "fetch_job", "claimed_until IS NOT NULL") == 0
    assert await _count(conn, "node") == 1


async def test_stop_lets_running_tasks_finish(conn, tmp_path, monkeypatch):
    monkeypatch.setattr(fetchloop, "IDLE_SLEEP_S", 0.01)
    gate = asyncio.Event()
    started = asyncio.Event()

    class SlowBrowser(FakeBrowser):
        async def capture(self, url, profile, *, click_through=False):
            started.set()
            await gate.wait()
            return await super().capture(url, profile, click_through=click_through)

    cfg = _cfg(tmp_path)
    await _queue(conn, "a.example.com")
    stop = asyncio.Event()
    task = asyncio.create_task(run_fetch(
        cfg, stop=stop, resolver=FakeResolver(), browser=SlowBrowser()))
    await asyncio.wait_for(started.wait(), 10)
    stop.set()
    await asyncio.sleep(0.05)
    assert not task.done()
    gate.set()
    await asyncio.wait_for(task, 10)
    assert await _count(conn, "attempt") == 1


async def test_rejected_result_is_logged_and_rolled_back(conn, tmp_path, monkeypatch,
                                                         caplog):
    async def reject(conn, *a, **kw):
        await conn.execute("INSERT INTO node (node_id, public_key) VALUES ('x', '\\x00')")
        raise ResultRejected("forged")

    monkeypatch.setattr(fetchloop, "store_result", reject)
    cfg = _cfg(tmp_path)
    await _queue(conn, "a.example.com")
    await _once(cfg)
    assert await _count(conn, "node", "node_id = 'x'") == 0
    assert await _count(conn, "attempt") == 0
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert errors and "forged" in errors[0].getMessage()


async def test_task_crash_keeps_loop_and_lease(conn, tmp_path, monkeypatch, caplog):
    async def boom(job, **kw):
        if job.fqdn == "a.example.com":
            raise RuntimeError("boom")
        return await real(job, **kw)

    real = fetchloop.run_job
    monkeypatch.setattr(fetchloop, "run_job", boom)
    cfg = _cfg(tmp_path, fetch_workers=2)
    await _queue(conn, "a.example.com", "b.example.com")
    await _once(cfg)
    assert await _count(conn, "attempt") == 1
    assert await _count(
        conn, "fetch_job",
        "fqdn = 'a.example.com' AND step = 0 AND claimed_until > now()") == 1
    crash = [r for r in caplog.records if r.exc_info and "a.example.com" in r.getMessage()]
    assert crash and crash[0].levelno == logging.ERROR


async def test_missing_asn_db_warns_once_and_runs(conn, tmp_path, caplog):
    cfg = _cfg(tmp_path, asn_mmdb=tmp_path / "missing.mmdb")
    await _queue(conn, "a.example.com")
    await _once(cfg)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "missing.mmdb" in warnings[0].getMessage()
    assert await _count(conn, "attempt", "asn_db_sha256 IS NULL") == 1


async def test_bad_asn_db_warns_once_and_runs(conn, tmp_path, caplog):
    bad = tmp_path / "bad.mmdb"
    bad.write_bytes(b"not an mmdb")
    cfg = _cfg(tmp_path, asn_mmdb=bad)
    await _queue(conn, "a.example.com")
    await _once(cfg)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "bad.mmdb" in warnings[0].getMessage()
    assert await _count(conn, "attempt") == 1


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    # once=True never sleeps, but keep any stray wait short.
    monkeypatch.setattr(fetchloop, "IDLE_SLEEP_S", 0.01, raising=False)
    monkeypatch.setattr(fetchloop, "CAP_SLEEP_S", 0.01, raising=False)


async def test_loaded_asn_snapshot_has_its_blob_row(conn, tmp_path, asn_mmdb):
    path = asn_mmdb()
    cfg = _cfg(tmp_path, asn_mmdb=path)
    await _once(cfg)  # nothing queued: no attempt, so no ASN hit
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    assert await _count(conn, "attempt") == 0
    assert await _count(conn, "blob", f"sha256 = '{sha}'") == 1


async def test_sweep_failure_does_not_block_claims(conn, tmp_path, monkeypatch, caplog):
    async def broken_sweep(*a, **k):
        raise RuntimeError("sweep broke")

    monkeypatch.setattr(fetchloop, "sweep", broken_sweep)
    cfg = _cfg(tmp_path)
    await _queue(conn, "a.example.com")
    await _once(cfg)
    assert await _count(conn, "attempt") == 1
    assert any("sweep" in r.getMessage() and r.exc_info for r in caplog.records)


async def test_unreadable_result_is_not_stored_and_logged_failed(conn, tmp_path, monkeypatch,
                                                                 caplog):
    # The outcome is read before storing, so "failed" is never logged for a
    # job whose attempt was stored.
    def unreadable(*a, **k):
        raise ValueError("cannot open")

    monkeypatch.setattr(fetchloop, "open_envelope", unreadable)
    cfg = _cfg(tmp_path)
    await _queue(conn, "a.example.com")
    await _once(cfg)
    assert any("failed" in r.getMessage() and r.exc_info for r in caplog.records)
    assert await _count(conn, "attempt") == 0
    assert "finished job" not in caplog.text


async def test_default_resolver_and_browser_are_built_from_config_and_closed(
        conn, tmp_path, monkeypatch):
    made = {}

    class StubResolver(FakeResolver):
        def __init__(self, nameservers, *, query_deadline_s):
            made["nameservers"] = (nameservers, query_deadline_s)

    class StubBrowser(FakeBrowser):
        def __init__(self, *, proxy, nav_timeout_s):
            super().__init__()
            made["browser"] = (proxy, nav_timeout_s)
            made["events"] = []

        async def __aenter__(self):
            made["events"].append("enter")
            return self

        async def __aexit__(self, *exc):
            made["events"].append("exit")

    monkeypatch.setattr(fetchloop, "Resolver", StubResolver)
    monkeypatch.setattr(fetchloop, "Browser", StubBrowser)
    cfg = _cfg(tmp_path, resolver_nameservers=("192.0.2.53",),
               resolver_query_deadline_s=4.5, fetch_proxy="socks5://127.0.0.1:9", nav_timeout_s=7)
    await _queue(conn, "a.example.com")
    await run_fetch(cfg, stop=asyncio.Event(), once=True)
    assert made["nameservers"] == (("192.0.2.53",), 4.5)
    assert made["browser"] == ("socks5://127.0.0.1:9", 7)
    assert made["events"] == ["enter", "exit"]
    assert await _count(conn, "attempt", "outcome = 'live'") == 1


async def test_asn_db_is_closed_when_fetch_ends(conn, tmp_path, asn_mmdb, monkeypatch):
    closed = []
    real_close = AsnDb.close
    monkeypatch.setattr(AsnDb, "close", lambda self: (closed.append(self), real_close(self))[1])
    await _once(_cfg(tmp_path, asn_mmdb=asn_mmdb()))
    assert len(closed) == 1


async def test_heartbeat_keeps_a_slow_job_leased_then_stops(conn, tmp_path, monkeypatch,
                                                            caplog):
    # lease_s = 1 and a capture that takes longer: without the heartbeat the
    # job would be claimable again while it runs.
    gate, started = asyncio.Event(), asyncio.Event()
    beats = []
    real_extend = fetchloop.extend_lease

    async def counting_extend(*a, **k):
        beats.append(True)
        return await real_extend(*a, **k)

    class SlowBrowser(FakeBrowser):
        async def capture(self, url, profile, *, click_through=False):
            started.set()
            await gate.wait()
            return await super().capture(url, profile, click_through=click_through)

    monkeypatch.setattr(fetchloop, "extend_lease", counting_extend)
    cfg = _cfg(tmp_path, lease_s=1)
    await _queue(conn, "a.example.com")
    task = asyncio.create_task(run_fetch(cfg, stop=asyncio.Event(), resolver=FakeResolver(),
                                         browser=SlowBrowser(), once=True))
    await asyncio.wait_for(started.wait(), 10)
    await asyncio.sleep(2.5)  # well past the first lease
    assert await claim_jobs(conn, 5, 1) == []  # a second claimer finds nothing due
    await conn.rollback()
    assert await _count(conn, "fetch_job", "claimed_until > now()") == 1
    assert len(beats) >= 3
    gate.set()
    await asyncio.wait_for(task, 10)
    assert await _count(conn, "attempt") == 1
    after = len(beats)
    await asyncio.sleep(0.8)  # more than two ticks
    assert len(beats) == after
    assert "lease lost" not in caplog.text


async def test_heartbeat_failure_is_logged_and_retried(conn, tmp_path, monkeypatch, caplog):
    gate, started = asyncio.Event(), asyncio.Event()
    calls = []
    real_extend = fetchloop.extend_lease

    async def flaky_extend(*a, **k):
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("db hiccup")
        return await real_extend(*a, **k)

    class SlowBrowser(FakeBrowser):
        async def capture(self, url, profile, *, click_through=False):
            started.set()
            await gate.wait()
            return await super().capture(url, profile, click_through=click_through)

    monkeypatch.setattr(fetchloop, "extend_lease", flaky_extend)
    cfg = _cfg(tmp_path, lease_s=1)
    await _queue(conn, "a.example.com")
    task = asyncio.create_task(run_fetch(cfg, stop=asyncio.Event(), resolver=FakeResolver(),
                                         browser=SlowBrowser(), once=True))
    await asyncio.wait_for(started.wait(), 10)
    while len(calls) < 2:
        await asyncio.sleep(0.05)
    gate.set()
    await asyncio.wait_for(task, 10)
    assert await _count(conn, "attempt", "outcome = 'live'") == 1
    assert any("lease extension failed" in r.getMessage() and r.exc_info
               for r in caplog.records)


async def test_node_key_is_loaded_off_the_event_loop(conn, tmp_path, monkeypatch):
    threads = []
    real = NodeKey.load_or_create.__func__

    def recording(cls, path):
        threads.append(threading.current_thread())
        return real(cls, path)

    monkeypatch.setattr(NodeKey, "load_or_create", classmethod(recording))
    await _once(_cfg(tmp_path))
    assert threads and threads[0] is not threading.main_thread()


class GatedBrowser(FakeBrowser):
    """Captures wait for ``gate``; ``started`` is set at the first capture."""

    def __init__(self):
        super().__init__()
        self.gate, self.started = asyncio.Event(), asyncio.Event()

    async def capture(self, url, profile, *, click_through=False):
        self.started.set()
        await self.gate.wait()
        return await super().capture(url, profile, click_through=click_through)


def _count_extends(monkeypatch):
    calls = []
    real = fetchloop.extend_lease

    async def counting(*a, **k):
        t = asyncio.get_running_loop().time()
        try:
            return await real(*a, **k)
        finally:
            calls.append(asyncio.get_running_loop().time() - t)

    monkeypatch.setattr(fetchloop, "extend_lease", counting)
    return calls


async def _until(pred, timeout=5.0):
    for _ in range(int(timeout / 0.02)):
        if pred():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not reached")


async def test_hung_job_times_out_stores_nothing_and_stays_leased(conn, tmp_path,
                                                                  monkeypatch, caplog):
    calls = _count_extends(monkeypatch)
    b = GatedBrowser()  # the gate never opens: the capture hangs
    cfg = _cfg(tmp_path, lease_s=1, job_timeout_s=0.8)
    await _queue(conn, "a.example.com")
    await asyncio.wait_for(_once(cfg, browser=b), 10)
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert any("a.example.com" in r.getMessage() and "timed out" in r.getMessage()
               for r in errors)
    assert await _count(conn, "attempt") == 0
    assert await _count(conn, "fetch_job", "step = 0 AND claimed_until > now()") == 1
    after = len(calls)
    await asyncio.sleep(0.8)
    assert len(calls) == after  # the heartbeat stopped with the job


async def test_heartbeat_stops_when_another_holder_claims(conn, tmp_path, monkeypatch,
                                                          caplog):
    calls = _count_extends(monkeypatch)
    b = GatedBrowser()
    cfg = _cfg(tmp_path, lease_s=1)
    await _queue(conn, "a.example.com")
    task = asyncio.create_task(run_fetch(cfg, stop=asyncio.Event(), resolver=FakeResolver(),
                                         browser=b, once=True))
    await asyncio.wait_for(b.started.wait(), 10)
    cur = await conn.execute(
        "UPDATE fetch_job SET claimed_until = now() + interval '1 hour' "
        "RETURNING claimed_until")
    theirs = (await cur.fetchone())[0]
    await conn.commit()
    await _until(lambda: "lease lost" in caplog.text)
    after = len(calls)
    await asyncio.sleep(0.8)
    assert len(calls) == after
    cur = await conn.execute("SELECT claimed_until FROM fetch_job")
    assert (await cur.fetchone())[0] == theirs  # never extended
    await conn.rollback()
    b.gate.set()
    await asyncio.wait_for(task, 10)


async def test_heartbeat_skips_a_locked_row_instead_of_waiting(conn, tmp_path,
                                                               monkeypatch, caplog):
    calls = _count_extends(monkeypatch)
    b = GatedBrowser()
    cfg = _cfg(tmp_path, lease_s=1)
    await _queue(conn, "a.example.com")
    task = asyncio.create_task(run_fetch(cfg, stop=asyncio.Event(), resolver=FakeResolver(),
                                         browser=b, once=True))
    await asyncio.wait_for(b.started.wait(), 10)
    locker = await connect(_test_db_url())
    try:
        await locker.execute("SELECT 1 FROM fetch_job FOR UPDATE")
        n = len(calls)
        await _until(lambda: len(calls) >= n + 2)  # ticks keep coming
        assert all(d < 1.0 for d in calls)  # none waited for the lock
    finally:
        await locker.close()
    n = len(calls)
    await _until(lambda: len(calls) >= n + 1)
    assert "lease extension failed" not in caplog.text and "lease lost" not in caplog.text
    b.gate.set()
    await asyncio.wait_for(task, 10)
    assert await _count(conn, "attempt") == 1
