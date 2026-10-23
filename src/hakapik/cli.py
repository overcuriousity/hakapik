"""Operator entry point: tail, stats, sample, prune."""

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


async def _with_conn(cfg: Config, fn, commit: bool = True):
    conn = await connect(cfg.database_url)
    try:
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
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=cfg.raw_retention_days)
    ).date()
    bs = BlobStore(cfg.data_dir / "blobs")
    n = asyncio.run(_with_conn(cfg, lambda c: prune_raw(c, bs, cutoff), commit=False))
    print(n)
    return 0


def _cmd_tail(cfg: Config, args) -> int:
    # Per-log rate and lag are logged by ingest itself (no extra network call).
    asyncio.run(ingest.run(cfg))
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


if __name__ == "__main__":
    sys.exit(main())
