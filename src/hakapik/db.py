"""Postgres schema and queries.

No function here commits; the caller owns the transaction.
"""

from dataclasses import dataclass
from datetime import date

import psycopg

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
