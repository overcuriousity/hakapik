import asyncio
import csv
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from hakapik import cli
from hakapik.blobstore import BlobStore
from hakapik.cli import main
from hakapik.db import (
    CandidateRow,
    add_candidates,
    add_raw_batch,
    bump_stat,
    connect,
    lock_blob,
    prune_raw,
)

needs_db = pytest.mark.skipif(
    not os.getenv("HAKAPIK_TEST_DB"), reason="needs postgres"
)


@pytest.fixture
def cfg_path(tmp_path):
    p = tmp_path / "cfg.toml"
    url = os.getenv("HAKAPIK_TEST_DB", "postgresql://unused/unused")
    p.write_text(f'data_dir = "{tmp_path / "data"}"\ndatabase_url = "{url}"\nraw_retention_days = 7\n')
    return str(p)


async def run_main(argv):
    # main() calls asyncio.run, so it must not share the test's running loop.
    return await asyncio.to_thread(main, argv)


def _cand(i, log_id="L"):
    return CandidateRow(f"h{i}.example.com", "example.com", log_id, i, b"k%d" % i, 1000 + i)


@needs_db
async def test_stats_prints_totals_row(capsys, conn, cfg_path):
    today = date.today()
    await bump_stat(conn, "A", today, entries=3, bytes=10, candidates=1)
    await bump_stat(conn, "B", today, entries=4, bytes=5, suppressed=2, supp_tranco=2)
    await bump_stat(conn, "B", today - timedelta(days=1), entries=6, bytes=1)
    await bump_stat(conn, "B", today - timedelta(days=30), entries=100)
    await conn.commit()
    assert await run_main(["--config", cfg_path, "stats"]) == 0
    out = capsys.readouterr().out.splitlines()
    header = out[0].split()
    assert header[:3] == ["log_id", "day", "entries"]
    assert "supp_tranco" in header and "supp_wildcard" in header
    assert len(out) == 1 + 3 + 1  # header, three rows within 7 days, total
    assert [line.split()[:2] for line in out[1:4]] == [
        ["A", str(today)], ["B", str(today - timedelta(days=1))], ["B", str(today)]
    ]
    total = out[-1].split()
    assert total[:2] == ["TOTAL", "-"]
    assert total[2:4] == ["13", "16"]  # entries, bytes (old row excluded)
    assert total[header.index("supp_tranco")] == "2"


@needs_db
async def test_sample_writes_csv(tmp_path, conn, cfg_path):
    await add_candidates(conn, [_cand(i) for i in range(5)])
    await conn.commit()
    out = tmp_path / "c.csv"
    assert await run_main(["--config", cfg_path, "sample", "--n", "2", "--out", str(out)]) == 0
    assert len(out.read_text().splitlines()) == 3
    with out.open() as f:
        rows = list(csv.DictReader(f))
    assert set(rows[0]) == {
        "fqdn", "registrable", "log_id", "log_index", "first_seen_ms", "created_at"
    }


async def _batch(conn, bs, log_id, start, end, data, age_days, age_hours=0):
    sha = bs.put(data, "application/octet-stream")
    await add_raw_batch(conn, log_id, start, end, sha, end - start + 1, len(data))
    ts = datetime.now(timezone.utc) - timedelta(days=age_days, hours=age_hours)
    await conn.execute(
        """UPDATE raw_batch SET created_at = %s
           WHERE blob_sha256 = %s AND log_id = %s AND start_index = %s""",
        (ts, sha, log_id, start),
    )
    return sha


@needs_db
async def test_prune_removes_raw_batches_without_candidates(tmp_path, conn, cfg_path):
    bs = BlobStore(tmp_path / "data" / "blobs")
    old = await _batch(conn, bs, "L", 0, 9, b"old", 30)
    fresh = await _batch(conn, bs, "L", 10, 19, b"fresh", 1)
    await conn.commit()
    assert await run_main(["--config", cfg_path, "prune"]) == 0
    cur = await conn.execute("SELECT blob_sha256 FROM raw_batch")
    assert [r[0] for r in await cur.fetchall()] == [fresh]
    assert not bs.path(old).exists()
    assert bs.path(fresh).exists()


@needs_db
async def test_prune_keeps_batch_with_candidate_in_range(tmp_path, conn, cfg_path, capsys):
    bs = BlobStore(tmp_path / "data" / "blobs")
    kept = await _batch(conn, bs, "L", 0, 9, b"keep", 30)
    # same index range on a different log must not protect it
    gone = await _batch(conn, bs, "M", 0, 9, b"gone", 30)
    await add_candidates(conn, [_cand(9, "L")])
    await conn.commit()
    assert await run_main(["--config", cfg_path, "prune"]) == 0
    assert capsys.readouterr().out.strip() == "1"
    assert bs.path(kept).exists()
    assert not bs.path(gone).exists()
    cur = await conn.execute("SELECT count(*) FROM raw_batch")
    assert (await cur.fetchone())[0] == 1


def test_missing_config_returns_1(tmp_path, capsys):
    assert main(["--config", str(tmp_path / "nope.toml"), "stats"]) == 1
    assert "nope.toml" in capsys.readouterr().err


def test_tail_dispatch(cfg_path, monkeypatch):
    calls = []

    async def fake_run(cfg):
        calls.append(cfg.data_dir)

    monkeypatch.setattr(cli.ingest, "run", fake_run)
    assert main(["--config", cfg_path, "tail"]) == 0
    assert len(calls) == 1


def test_main_quiets_httpx_request_logging(cfg_path, monkeypatch):
    import logging

    async def fake_run(cfg):
        pass

    monkeypatch.setattr(cli.ingest, "run", fake_run)
    main(["--config", cfg_path, "tail"])
    assert logging.getLogger("httpx").getEffectiveLevel() == logging.WARNING


@needs_db
async def test_prune_commit_failure_keeps_blob_and_row(tmp_path, conn, monkeypatch):
    bs = BlobStore(tmp_path / "blobs")
    sha = await _batch(conn, bs, "L", 0, 9, b"old", 30)
    await conn.commit()

    async def boom():
        raise RuntimeError("commit failed")

    monkeypatch.setattr(conn, "commit", boom)
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    with pytest.raises(RuntimeError, match="commit failed"):
        await prune_raw(conn, bs, cutoff)
    monkeypatch.undo()
    await conn.rollback()
    assert bs.path(sha).exists()
    cur = await conn.execute("SELECT count(*) FROM raw_batch")
    assert (await cur.fetchone())[0] == 1


@needs_db
async def test_prune_skips_invalid_digest(tmp_path, conn):
    bs = BlobStore(tmp_path / "blobs")
    good = await _batch(conn, bs, "L", 0, 9, b"old", 30)
    await add_raw_batch(conn, "L", 10, 19, "../../etc/passwd", 10, 3)
    await conn.execute(
        "UPDATE raw_batch SET created_at = now() - interval '30 days' WHERE start_index = 10"
    )
    await conn.commit()
    assert await prune_raw(conn, bs, datetime.now(timezone.utc) - timedelta(days=7)) == 2
    assert not bs.path(good).exists()


@pytest.mark.parametrize("exc", [asyncio.CancelledError, KeyboardInterrupt])
def test_second_interrupt_exits_130_without_traceback(tmp_path, capsys, monkeypatch, exc):
    # A second Ctrl-C cancels the run; the operator gets one line, not a traceback.
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'data_dir = "{tmp_path}"\ndatabase_url = "postgresql://unused"\n')

    def interrupted(cfg, args):
        raise exc()

    monkeypatch.setattr(cli, "_cmd_tail", interrupted)
    assert main(["--config", str(cfg), "tail"]) == 130
    assert capsys.readouterr().err.strip().endswith("hakapik: interrupted")


def _cutoff(days=7):
    return datetime.now(timezone.utc) - timedelta(days=days)


@needs_db
async def test_prune_cutoff_is_a_timestamp_not_a_date(tmp_path, conn, cfg_path):
    # retention 7 days: an hour short of it is kept, an hour past it pruned,
    # whatever the time of day (a date cutoff would be off by up to a day).
    bs = BlobStore(tmp_path / "data" / "blobs")
    young = await _batch(conn, bs, "L", 0, 9, b"young", 7, age_hours=-1)
    old = await _batch(conn, bs, "L", 10, 19, b"old", 7, age_hours=1)
    await conn.commit()
    assert await run_main(["--config", cfg_path, "prune"]) == 0
    assert bs.path(young).exists() and not bs.path(old).exists()


@needs_db
async def test_prune_keeps_a_blob_shared_with_a_remaining_batch(tmp_path, conn):
    bs = BlobStore(tmp_path / "blobs")
    old = await _batch(conn, bs, "L", 0, 9, b"same", 30)
    again = await _batch(conn, bs, "L", 20, 29, b"same", 1)  # same bytes, fresh
    assert old == again
    await conn.commit()
    assert await prune_raw(conn, bs, _cutoff()) == 1
    assert bs.path(old).exists()


@needs_db
async def test_prune_tolerates_a_blob_file_already_gone(tmp_path, conn):
    bs = BlobStore(tmp_path / "blobs")
    gone = await _batch(conn, bs, "L", 0, 9, b"gone", 30)
    other = await _batch(conn, bs, "L", 10, 19, b"other", 30)
    await conn.commit()
    os.chmod(bs.path(gone), 0o644)
    bs.path(gone).unlink()
    assert await prune_raw(conn, bs, _cutoff()) == 2
    assert not bs.path(other).exists()


@needs_db
async def test_prune_keeps_batch_with_candidate_at_start_index(tmp_path, conn):
    bs = BlobStore(tmp_path / "blobs")
    kept = await _batch(conn, bs, "L", 10, 19, b"keep", 30)
    await add_candidates(conn, [_cand(10, "L")])
    await conn.commit()
    assert await prune_raw(conn, bs, _cutoff()) == 0
    assert bs.path(kept).exists()


@needs_db
async def test_prune_unlink_error_is_logged_and_the_rest_continue(
    tmp_path, conn, monkeypatch, caplog
):
    bs = BlobStore(tmp_path / "blobs")
    stuck = await _batch(conn, bs, "L", 0, 9, b"stuck", 30)
    other = await _batch(conn, bs, "L", 10, 19, b"other", 30)
    await conn.commit()
    real_unlink = Path.unlink

    def unlink(self, *a, **kw):
        if self.name == stuck:
            raise PermissionError("read-only filesystem")
        return real_unlink(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", unlink)
    with caplog.at_level("WARNING"):
        assert await prune_raw(conn, bs, _cutoff()) == 2
    assert f"cannot unlink blob {stuck}" in caplog.text
    assert bs.path(stuck).exists() and not bs.path(other).exists()


@needs_db
async def test_prune_waits_for_a_batch_about_to_reference_the_blob(tmp_path, conn):
    # Ingest found the blob existing (put() kept it) and holds lock_blob until
    # its row commits; prune must not unlink the blob in between.
    bs = BlobStore(tmp_path / "blobs")
    sha = await _batch(conn, bs, "L", 0, 9, b"same", 30)
    await conn.commit()
    ingest_conn = await connect(os.environ["HAKAPIK_TEST_DB"])
    try:
        await lock_blob(ingest_conn, sha)
        assert bs.put(b"same", "application/octet-stream") == sha
        await add_raw_batch(ingest_conn, "L", 0, 9, sha, 10, 4)
        prune = asyncio.create_task(prune_raw(conn, bs, _cutoff()))
        await asyncio.sleep(0.2)
        assert not prune.done()  # deleted the old row, now waits on the lock
        await ingest_conn.commit()
        assert await prune == 1
    finally:
        await ingest_conn.close()
    assert bs.path(sha).exists()
