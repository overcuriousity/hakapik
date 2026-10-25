"""Operator entry point: tail, stats, sample, prune, enqueue, fetch, show."""

from __future__ import annotations

import argparse
import asyncio
import csv
import logging
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from hakapik import fetchloop, ingest
from hakapik.blobstore import BlobStore
from hakapik.config import Config, load_config
from hakapik.db import (
    STAT_COLUMNS,
    connect,
    migrate,
    prune_raw,
    read_stats,
    sample_candidates,
    sweep_orphan_blobs,
)
from hakapik.jobs import enqueue_manual, show_fqdn
from hakapik.names import normalize
from hakapik.signals import stop_on_signals

log = logging.getLogger("hakapik.cli")

SAMPLE_COLUMNS = (
    "fqdn", "registrable", "log_id", "log_index", "first_seen_ms", "created_at"
)


async def _with_conn(cfg: Config, fn, commit: bool = True):
    conn = await connect(cfg.database_url)
    try:
        # Every command migrates, the read-only ones (stats, sample, show)
        # too: on a fresh or older database they then see the current schema
        # instead of failing. Once the schema is current, migrate changes
        # nothing and takes no lock that conflicts with a writer (db.migrate's
        # checks), so it does not block a running tail or fetch.
        await migrate(conn)
        result = await fn(conn)
        if commit:
            await conn.commit()
        return result
    finally:
        await conn.close()


def _format_stats(rows: list[dict]) -> str:
    keys = ("log_id", "day")
    header = [*keys, *STAT_COLUMNS]
    body = [
        [r["log_id"], str(r["day"]), *(str(r[c]) for c in STAT_COLUMNS)]
        for r in rows
    ]
    total = ["TOTAL", "-", *(str(sum(r[c] for r in rows)) for c in STAT_COLUMNS)]
    table = [header, *body, total]
    widths = [max(len(row[i]) for row in table) for i in range(len(header))]
    return "\n".join(
        "  ".join(cell.ljust(widths[i]) if i < len(keys) else cell.rjust(widths[i])
                  for i, cell in enumerate(row)).rstrip()
        for row in table
    )


def _cmd_stats(cfg: Config, args) -> int:
    since = args.since or (date.today() - timedelta(days=7))
    rows = asyncio.run(_with_conn(cfg, lambda c: read_stats(c, since)))
    print(_format_stats(rows))
    return 0


def _cmd_sample(cfg: Config, args) -> int:
    rows = asyncio.run(_with_conn(cfg, lambda c: sample_candidates(c, args.n)))
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SAMPLE_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    return 0


def _cmd_prune(cfg: Config, args) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=cfg.raw_retention_days)
    bs = BlobStore(cfg.data_dir / "blobs")

    async def prune(conn):
        batches = await prune_raw(conn, bs, cutoff)
        orphans, tmps = await sweep_orphan_blobs(conn, bs, cfg.orphan_margin_hours * 3600)
        return batches, orphans, tmps

    batches, orphans, tmps = asyncio.run(_with_conn(cfg, prune, commit=False))
    print(f"raw_batches\t{batches}\norphan_blobs\t{orphans}\ntemp_files\t{tmps}")
    return 0


def _cmd_tail(cfg: Config, args) -> int:
    # Per-log rate and lag are logged by ingest itself (no extra network call).
    asyncio.run(ingest.run(cfg))
    return 0


def _read_names_file(path: Path) -> list[str]:
    lines = (ln.strip() for ln in path.read_text().splitlines())
    return [ln for ln in lines if ln and not ln.startswith("#")]


def _cmd_enqueue(cfg: Config, args) -> int:
    names = [*args.names, *(_read_names_file(args.file) if args.file else [])]
    if not names:
        args.parser.error("enqueue needs at least one name or --file")
    results = asyncio.run(_with_conn(cfg, lambda c: enqueue_manual(c, names)))
    for name, status in results:
        print(f"{name}\t{status}")
    return 0


async def _fetch(cfg: Config, once: bool) -> None:
    stop = asyncio.Event()
    with stop_on_signals(stop):
        await fetchloop.run_fetch(cfg, stop=stop, once=once)


def _cmd_fetch(cfg: Config, args) -> int:
    asyncio.run(_fetch(cfg, args.once))
    return 0


def _format_show(fqdn: str, cands: list[dict]) -> str:
    def v(x) -> str:
        return "-" if x is None else str(x)

    lines = [fqdn]
    for c in cands:
        lines.append(f"candidate {c['id']}  reason {c['reason']}  created {c['created_at']}")
        for j in c["jobs"]:
            lines.append(f"  job  state {j['state']}  step {j['step']}  due {j['due_at']}")
            for a in j["attempts"]:
                lines.append(
                    f"    attempt {a['step']}  {a['started_at']}  {a['outcome']}"
                    f"  http {v(a['http_status'])}  {v(a['final_url'])}"
                    f"  asn {v(a['asn'])}  {v(a['asn_org'])}"
                )
        m = c["manifest"]
        lines.append(
            f"  manifest v{m['version']}  {m['sha256']}" if m else "  manifest -"
        )
    return "\n".join(lines)


def _cmd_show(cfg: Config, args) -> int:
    rec = normalize(args.fqdn)
    cands = (
        asyncio.run(_with_conn(cfg, lambda c: show_fqdn(c, rec.fqdn), commit=False))
        if rec.valid else []
    )
    if not cands:
        print(f"hakapik: error: no candidate for {args.fqdn}", file=sys.stderr)
        return 1
    print(_format_show(rec.fqdn, cands))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hakapik")
    p.add_argument("--config", required=True, type=Path)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("tail").set_defaults(func=_cmd_tail)
    st = sub.add_parser("stats")
    st.add_argument("--since", type=date.fromisoformat, metavar="YYYY-MM-DD")
    st.set_defaults(func=_cmd_stats)
    sa = sub.add_parser("sample")
    sa.add_argument("--n", type=int, required=True)
    sa.add_argument("--out", type=Path, required=True)
    sa.set_defaults(func=_cmd_sample)
    sub.add_parser("prune").set_defaults(func=_cmd_prune)
    en = sub.add_parser("enqueue")
    en.add_argument("names", nargs="*", metavar="NAME")
    en.add_argument("--file", type=Path, help="one name per line; # starts a comment")
    en.set_defaults(func=_cmd_enqueue, parser=en)
    fe = sub.add_parser("fetch")
    fe.add_argument("--once", action="store_true", help="one iteration, then exit")
    fe.set_defaults(func=_cmd_fetch)
    sh = sub.add_parser("show")
    sh.add_argument("fqdn", metavar="FQDN")
    sh.set_defaults(func=_cmd_show)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one INFO line per request
    try:
        cfg = load_config(args.config)
        return args.func(cfg, args)
    except Exception as e:  # operator-facing: message, not traceback
        print(f"hakapik: error: {e}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, asyncio.CancelledError):  # second Ctrl-C
        print("hakapik: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
