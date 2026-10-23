"""Postgres schema and queries.

No function here commits; the caller owns the transaction.
"""

import os
from dataclasses import dataclass
from datetime import date

import psycopg
from psycopg.rows import dict_row

from hakapik.blobstore import BlobStore

_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS log_cursor (
        log_id text PRIMARY KEY,
        next_index bigint NOT NULL,
        bootstrap_done boolean NOT NULL,
        updated_at timestamptz NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS raw_batch (
        id bigserial PRIMARY KEY,
        log_id text NOT NULL,
        start_index bigint NOT NULL,
        end_index bigint NOT NULL,
        blob_sha256 text NOT NULL,
        entries int NOT NULL,
        bytes int NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS candidate (
        id bigserial PRIMARY KEY,
        fqdn text NOT NULL,
        registrable text NOT NULL,
        log_id text NOT NULL,
        log_index bigint NOT NULL,
        cert_key bytea NOT NULL,
        first_seen_ms bigint NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS ingest_stat (
        log_id text NOT NULL,
        day date NOT NULL,
        entries bigint NOT NULL DEFAULT 0,
        bytes bigint NOT NULL DEFAULT 0,
        parse_failed bigint NOT NULL DEFAULT 0,
        certs_unique bigint NOT NULL DEFAULT 0,
        fqdns_new bigint NOT NULL DEFAULT 0,
        suppressed bigint NOT NULL DEFAULT 0,
        candidates bigint NOT NULL DEFAULT 0,
        PRIMARY KEY (log_id, day)
    )""",
]

STAT_COLUMNS = (
    "entries",
    "bytes",
    "parse_failed",
    "certs_unique",
    "fqdns_new",
    "suppressed",
    "candidates",
)


@dataclass(frozen=True)
class CandidateRow:
    fqdn: str
    registrable: str
    log_id: str
    log_index: int
    cert_key: bytes
    first_seen_ms: int


async def connect(url: str) -> psycopg.AsyncConnection:
    return await psycopg.AsyncConnection.connect(url, autocommit=False)


async def migrate(conn: psycopg.AsyncConnection) -> None:
    for stmt in _SCHEMA:
        await conn.execute(stmt)
    await conn.commit()


async def get_cursor(conn: psycopg.AsyncConnection, log_id: str) -> tuple[int, bool]:
    cur = await conn.execute(
        "SELECT next_index, bootstrap_done FROM log_cursor WHERE log_id = %s",
        (log_id,),
    )
    row = await cur.fetchone()
    return (0, False) if row is None else (row[0], row[1])


async def set_cursor(
    conn: psycopg.AsyncConnection, log_id: str, next_index: int, bootstrap_done: bool
) -> None:
    await conn.execute(
        """INSERT INTO log_cursor (log_id, next_index, bootstrap_done)
           VALUES (%s, %s, %s)
           ON CONFLICT (log_id) DO UPDATE SET
             next_index = EXCLUDED.next_index,
             bootstrap_done = EXCLUDED.bootstrap_done,
             updated_at = now()""",
        (log_id, next_index, bootstrap_done),
    )


async def add_candidates(
    conn: psycopg.AsyncConnection, rows: list[CandidateRow]
) -> None:
    async with conn.cursor() as cur:
        await cur.executemany(
            """INSERT INTO candidate
                 (fqdn, registrable, log_id, log_index, cert_key, first_seen_ms)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            [
                (r.fqdn, r.registrable, r.log_id, r.log_index, r.cert_key, r.first_seen_ms)
                for r in rows
            ],
        )


async def add_raw_batch(
    conn: psycopg.AsyncConnection,
    log_id: str,
    start_index: int,
    end_index: int,
    blob_sha256: str,
    entries: int,
    nbytes: int,
) -> None:
    await conn.execute(
        """INSERT INTO raw_batch
             (log_id, start_index, end_index, blob_sha256, entries, bytes)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (log_id, start_index, end_index, blob_sha256, entries, nbytes),
    )


async def bump_stat(
    conn: psycopg.AsyncConnection, log_id: str, day: date, **increments: int
) -> None:
    unknown = set(increments) - set(STAT_COLUMNS)
    if unknown:
        raise ValueError(f"unknown ingest_stat columns: {sorted(unknown)}")
    if not increments:
        return
    cols = list(increments)  # validated against STAT_COLUMNS, safe to interpolate
    sql = (
        f"INSERT INTO ingest_stat (log_id, day, {', '.join(cols)}) "
        f"VALUES (%s, %s, {', '.join(['%s'] * len(cols))}) "
        "ON CONFLICT (log_id, day) DO UPDATE SET "
        + ", ".join(f"{c} = ingest_stat.{c} + EXCLUDED.{c}" for c in cols)
    )
    await conn.execute(sql, (log_id, day, *increments.values()))


async def read_stat(conn: psycopg.AsyncConnection, log_id: str, day: date) -> dict:
    cur = await conn.execute(
        f"SELECT {', '.join(STAT_COLUMNS)} FROM ingest_stat "
        "WHERE log_id = %s AND day = %s",
        (log_id, day),
    )
    row = await cur.fetchone()
    return dict(zip(STAT_COLUMNS, row)) if row else dict.fromkeys(STAT_COLUMNS, 0)


async def read_stats(conn: psycopg.AsyncConnection, since: date) -> list[dict]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            f"SELECT log_id, day, {', '.join(STAT_COLUMNS)} FROM ingest_stat "
            "WHERE day >= %s ORDER BY log_id, day",
            (since,),
        )
        return await cur.fetchall()


async def sample_candidates(conn: psycopg.AsyncConnection, n: int) -> list[dict]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT fqdn, registrable, log_id, log_index, first_seen_ms, created_at "
            "FROM candidate ORDER BY random() LIMIT %s",
            (n,),
        )
        return await cur.fetchall()


async def prune_raw(
    conn: psycopg.AsyncConnection, bs: BlobStore, older_than: date
) -> int:
    """Delete raw batches older than ``older_than`` that hold no candidate.

    A batch is kept if any candidate on the same log has a log_index inside
    its [start_index, end_index]. Blob files are unlinked unless another
    remaining batch still references the same (content-addressed) blob.

    This is the one db function that commits: file deletion must follow a
    durable delete, so the DELETE is committed before any blob is unlinked.
    If the commit fails, the exception propagates and no file is touched.
    """
    cur = await conn.execute(
        """DELETE FROM raw_batch rb
           WHERE rb.created_at < %s
             AND NOT EXISTS (
               SELECT 1 FROM candidate c
               WHERE c.log_id = rb.log_id
                 AND c.log_index BETWEEN rb.start_index AND rb.end_index)
           RETURNING rb.blob_sha256""",
        (older_than,),
    )
    shas = {r[0] for r in await cur.fetchall()}
    count = cur.rowcount
    await conn.commit()
    for sha in shas:
        cur = await conn.execute(
            "SELECT 1 FROM raw_batch WHERE blob_sha256 = %s LIMIT 1", (sha,)
        )
        if await cur.fetchone():
            continue
        path = bs.path(sha)
        try:
            os.chmod(path, 0o644)
            path.unlink()
        except FileNotFoundError:
            pass
    return count
