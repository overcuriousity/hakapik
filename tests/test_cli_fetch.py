import asyncio
import os

import pytest

from hakapik.cli import main
from hakapik.jobs import enqueue_manual


@pytest.fixture
def cfg_file(tmp_path):
    url = os.getenv("HAKAPIK_TEST_DB")
    if not url:
        pytest.skip("needs postgres (set HAKAPIK_TEST_DB)")
    p = tmp_path / "hakapik.toml"
    p.write_text(f'data_dir = "{tmp_path}"\ndatabase_url = "{url}"\n')
    return p


async def run_main(argv):
    # main() calls asyncio.run, so it must not share the test's running loop.
    return await asyncio.to_thread(main, argv)


async def test_enqueue_cli(cfg_file, conn, capsys):
    await conn.commit()
    rc = await run_main(["--config", str(cfg_file), "enqueue", "Sparkasse-Prüfung.de", "*.x.com"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Sparkasse-Prüfung.de\tqueued" in out and "*.x.com\twildcard" in out


async def test_enqueue_file_and_dupes(cfg_file, conn, capsys, tmp_path):
    await conn.commit()
    f = tmp_path / "names.txt"
    f.write_text("# comment\n\nb.example.com\n  c.example.com  \n")
    rc = await run_main(["--config", str(cfg_file), "enqueue", "a.example.com", "b.example.com",
                         "--file", str(f)])
    assert rc == 0
    assert capsys.readouterr().out.splitlines() == [
        "a.example.com\tqueued", "b.example.com\tqueued",
        "b.example.com\talready_open", "c.example.com\tqueued",
    ]


async def test_enqueue_no_names_exits_2(cfg_file, capsys):
    with pytest.raises(SystemExit) as e:
        await run_main(["--config", str(cfg_file), "enqueue"])
    assert e.value.code == 2


async def test_show_unknown_name_exits_1(cfg_file, conn, capsys):
    await conn.commit()
    assert await run_main(["--config", str(cfg_file), "show", "nope.example"]) == 1
    assert "no candidate" in capsys.readouterr().err


async def test_show_after_enqueue(cfg_file, conn, capsys):
    await enqueue_manual(conn, ["Sparkasse-Prüfung.de"])
    await conn.commit()
    rc = await run_main(["--config", str(cfg_file), "show", "Sparkasse-Prüfung.de"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "xn--sparkasse-prfung-" in out
    assert "reason manual" in out and "state open" in out and "step 0" in out
    assert "manifest -" in out


def test_fetch_help(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--config", "x.toml", "fetch", "--help"])
    assert e.value.code == 0
    assert "--once" in capsys.readouterr().out


def test_fetch_first_signal_stops_cleanly(tmp_path, monkeypatch, capsys):
    import signal

    from hakapik import fetchloop

    cfg = tmp_path / "c.toml"
    cfg.write_text(f'data_dir = "{tmp_path}"\ndatabase_url = "postgresql://unused"\n')
    seen = {}

    async def fake_run_fetch(cfg, *, stop, once):
        seen["once"] = once
        os.kill(os.getpid(), signal.SIGINT)
        await stop.wait()

    monkeypatch.setattr(fetchloop, "run_fetch", fake_run_fetch)
    assert main(["--config", str(cfg), "fetch", "--once"]) == 0
    assert seen == {"once": True}
    assert capsys.readouterr().err == ""


def test_fetch_second_signal_exits_130_without_traceback(tmp_path, monkeypatch, capsys):
    import signal

    from hakapik import fetchloop

    cfg = tmp_path / "c.toml"
    cfg.write_text(f'data_dir = "{tmp_path}"\ndatabase_url = "postgresql://unused"\n')

    async def stuck_run_fetch(cfg, *, stop, once):
        os.kill(os.getpid(), signal.SIGINT)
        await stop.wait()
        os.kill(os.getpid(), signal.SIGINT)  # the operator presses Ctrl-C again
        await asyncio.Event().wait()  # a capture that does not end on stop

    monkeypatch.setattr(fetchloop, "run_fetch", stuck_run_fetch)
    assert main(["--config", str(cfg), "fetch"]) == 130
    err = capsys.readouterr().err
    assert err.strip() == "hakapik: interrupted"
    assert "Traceback" not in err


async def _history(conn):
    """Two candidates for a.example.com: one with two attempts and two manifests."""
    from hakapik.db import CandidateRow, add_candidates

    await add_candidates(conn, [CandidateRow("a.example.com", "example.com", "L", 1, b"k", 1)])
    cur = await conn.execute("UPDATE fetch_job SET state = 'done', step = 1 RETURNING id, candidate_id")
    jid, cid = await cur.fetchone()
    await conn.execute("INSERT INTO node (node_id, public_key) VALUES ('n', 'k')")
    for sha in ("env0", "env1", "m1", "m2"):
        await conn.execute(
            "INSERT INTO blob (sha256, size, media_type) VALUES (%s, 1, 'x')", (sha,)
        )
    await conn.execute(
        """INSERT INTO attempt (job_id, step, node_id, started_at, finished_at, outcome,
                                http_status, final_url, envelope_sha256, asn, asn_org)
           VALUES (%s, 0, 'n', now(), now(), 'live', 200, 'https://a.example.com/',
                   'env0', 64500, 'Example AS'),
                  (%s, 1, 'n', now(), now(), 'nxdomain', NULL, NULL, 'env1', NULL, NULL)""",
        (jid, jid),
    )
    await conn.execute(
        """INSERT INTO manifest (candidate_id, version, sha256, prev_sha256)
           VALUES (%s, 1, 'm1', NULL), (%s, 2, 'm2', 'm1')""",
        (cid, cid),
    )
    await enqueue_manual(conn, ["a.example.com"])
    await conn.commit()


async def test_show_lists_attempts_and_latest_manifest(cfg_file, conn, capsys):
    await _history(conn)
    rc = await run_main(["--config", str(cfg_file), "show", "A.Example.com"])
    assert rc == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "a.example.com"
    assert lines[1].startswith("candidate ") and "reason first_seen" in lines[1]
    assert "state done  step 1" in lines[2]
    assert "attempt 0" in lines[3] and "live  http 200  https://a.example.com/" in lines[3]
    assert lines[3].endswith("asn 64500  Example AS")
    assert "attempt 1" in lines[4] and "nxdomain  http -  -  asn -  -" in lines[4]
    assert lines[5] == "  manifest v2  m2"
    assert "reason manual" in lines[6] and "state open  step 0" in lines[7]
    assert lines[8] == "  manifest -"
    assert len(lines) == 9


async def test_show_fqdn_query_count_does_not_grow_with_history(conn):
    from hakapik.jobs import show_fqdn

    await _history(conn)
    calls = 0
    real = conn.execute

    async def counting(*a, **kw):
        nonlocal calls
        calls += 1
        return await real(*a, **kw)

    conn.execute = counting
    try:
        out = await show_fqdn(conn, "a.example.com")
    finally:
        del conn.execute
    assert [len(c["jobs"]) for c in out] == [1, 1]
    assert [len(j["attempts"]) for c in out for j in c["jobs"]] == [2, 0]
    assert calls <= 4  # candidates, jobs, attempts, manifests
