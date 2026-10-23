"""Operator entry point: bootstrap, tail, stats, sample, prune."""

from __future__ import annotations

import argparse
import asyncio
import csv
import logging
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from hakapik import ingest
from hakapik.blobstore import BlobStore
from hakapik.config import Config, load_config
from hakapik.db import (
    STAT_COLUMNS,
    connect,
    migrate,
    prune_raw,
    read_stats,
    sample_candidates,
)

log = logging.getLogger("hakapik.cli")

SAMPLE_COLUMNS = (
    "fqdn", "registrable", "log_id", "log_index", "first_seen_ms", "created_at"
)


async def _lag_loop(cfg: Config, interval: float = 60) -> None:
    """Log each log's cursor every ``interval`` s.

    The tree size is not known without a network call, so this logs
    next_index per log, not lag.
    """
    conn = await connect(cfg.database_url)
    try:
        while True:
            await asyncio.sleep(interval)
            cur = await conn.execute(
                "SELECT log_id, next_index FROM log_cursor ORDER BY log_id"
            )
            rows = await cur.fetchall()
            await conn.rollback()
            for log_id, next_index in rows:
                log.info("cursor log=%s next_index=%d", log_id, next_index)
    finally:
        await conn.close()


async def _run_ingest(cfg: Config, mode: str) -> None:
    lag = asyncio.create_task(_lag_loop(cfg)) if mode == "tail" else None
    try:
        await ingest.run(cfg, mode)
    finally:
        if lag:
            lag.cancel()
            await asyncio.gather(lag, return_exceptions=True)


async def _with_conn(cfg: Config, fn):
    conn = await connect(cfg.database_url)
    try:
        await migrate(conn)
        result = await fn(conn)
        await conn.commit()
        return result
    finally:
        await conn.close()


def _format_stats(rows: list[dict]) -> str:
    header = ["log_id", "day", *STAT_COLUMNS]
    body = [[r["log_id"], str(r["day"]), *(str(r[c]) for c in STAT_COLUMNS)] for r in rows]
    total = ["TOTAL", "-", *(str(sum(r[c] for r in rows)) for c in STAT_COLUMNS)]
    table = [header, *body, total]
    widths = [max(len(row[i]) for row in table) for i in range(len(header))]
    return "\n".join(
        "  ".join(cell.ljust(widths[i]) if i < 2 else cell.rjust(widths[i])
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
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=cfg.raw_retention_days)
    ).date()
    bs = BlobStore(cfg.data_dir / "blobs")
    n = asyncio.run(_with_conn(cfg, lambda c: prune_raw(c, bs, cutoff)))
    print(n)
    return 0


def _cmd_ingest(cfg: Config, args) -> int:
    asyncio.run(_run_ingest(cfg, args.command))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hakapik")
    p.add_argument("--config", required=True, type=Path)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("bootstrap").set_defaults(func=_cmd_ingest)
    sub.add_parser("tail").set_defaults(func=_cmd_ingest)
    st = sub.add_parser("stats")
    st.add_argument("--since", type=date.fromisoformat, metavar="YYYY-MM-DD")
    st.set_defaults(func=_cmd_stats)
    sa = sub.add_parser("sample")
    sa.add_argument("--n", type=int, required=True)
    sa.add_argument("--out", type=Path, required=True)
    sa.set_defaults(func=_cmd_sample)
    sub.add_parser("prune").set_defaults(func=_cmd_prune)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    try:
        cfg = load_config(args.config)
        return args.func(cfg, args)
    except Exception as e:  # operator-facing: message, not traceback
        print(f"hakapik: error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
