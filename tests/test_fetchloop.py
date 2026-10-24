import asyncio
import hashlib
import logging

import pytest
from conftest import _test_db_url
from test_worker import T, FakeBrowser

from hakapik import fetchloop
from hakapik.asn import AsnDb
from hakapik.config import Config
from hakapik.fetchloop import run_fetch
from hakapik.jobs import enqueue_manual
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
        def __init__(self, nameservers):
            made["nameservers"] = nameservers

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
               fetch_proxy="socks5://127.0.0.1:9", nav_timeout_s=7)
    await _queue(conn, "a.example.com")
    await run_fetch(cfg, stop=asyncio.Event(), once=True)
    assert made["nameservers"] == ("192.0.2.53",)
    assert made["browser"] == ("socks5://127.0.0.1:9", 7)
    assert made["events"] == ["enter", "exit"]
    assert await _count(conn, "attempt", "outcome = 'live'") == 1


async def test_asn_db_is_closed_when_fetch_ends(conn, tmp_path, asn_mmdb, monkeypatch):
    closed = []
    real_close = AsnDb.close
    monkeypatch.setattr(AsnDb, "close", lambda self: (closed.append(self), real_close(self))[1])
    await _once(_cfg(tmp_path, asn_mmdb=asn_mmdb()))
    assert len(closed) == 1
