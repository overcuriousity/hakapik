"""Postgres schema and queries.

No function here commits; the caller owns the transaction.
"""

import logging
import os
from dataclasses import dataclass
from datetime import date

import psycopg
from psycopg.rows import dict_row

from hakapik.blobstore import BlobStore

_log = logging.getLogger(__name__)

_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS log_cursor (
        log_id text PRIMARY KEY,
        next_index bigint NOT NULL,
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
        supp_tranco bigint NOT NULL DEFAULT 0,
        supp_public_apex bigint NOT NULL DEFAULT 0,
        supp_wildcard bigint NOT NULL DEFAULT 0,
        candidates bigint NOT NULL DEFAULT 0,
        PRIMARY KEY (log_id, day)
    )""",
    """CREATE TABLE IF NOT EXISTS fetch_job (
        id bigserial PRIMARY KEY,
        candidate_id bigint NOT NULL REFERENCES candidate(id),
        fqdn text NOT NULL,
        registrable text NOT NULL,
        priority real NOT NULL DEFAULT 0,
        step int NOT NULL DEFAULT 0,
        due_at timestamptz NOT NULL,
        state text NOT NULL DEFAULT 'open',
        claimed_until timestamptz,
        created_at timestamptz NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS node (
        node_id text PRIMARY KEY,
        public_key bytea NOT NULL,
        added_at timestamptz NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS blob (
        sha256 text PRIMARY KEY,
        size bigint NOT NULL,
        media_type text NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS attempt (
        id bigserial PRIMARY KEY,
        job_id bigint NOT NULL REFERENCES fetch_job(id),
        step int NOT NULL,
        node_id text NOT NULL REFERENCES node(node_id),
        egress_address text,
        started_at timestamptz NOT NULL,
        finished_at timestamptz NOT NULL,
        outcome text NOT NULL,
        http_status int,
        final_url text,
        error text,
        envelope_sha256 text NOT NULL REFERENCES blob(sha256),
        asn bigint,
        asn_org text,
        asn_db_sha256 text REFERENCES blob(sha256),
        UNIQUE (job_id, step)
    )""",
    """CREATE TABLE IF NOT EXISTS dns_answer (
        id bigserial PRIMARY KEY,
        attempt_id bigint NOT NULL REFERENCES attempt(id),
        node_id text NOT NULL,
        qname text NOT NULL,
        rrtype text NOT NULL,
        rcode text NOT NULL,
        ttl int,
        answers text[] NOT NULL,
        resolver text NOT NULL,
        queried_at timestamptz NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS artifact (
        id bigserial PRIMARY KEY,
        attempt_id bigint NOT NULL REFERENCES attempt(id),
        profile text NOT NULL,
        kind text NOT NULL,
        sha256 text NOT NULL REFERENCES blob(sha256)
    )""",
    """CREATE TABLE IF NOT EXISTS manifest (
        id bigserial PRIMARY KEY,
        candidate_id bigint NOT NULL REFERENCES candidate(id),
        version int NOT NULL,
        sha256 text NOT NULL REFERENCES blob(sha256),
        prev_sha256 text,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (candidate_id, version)
    )""",
]

# (index name, DDL). CREATE INDEX IF NOT EXISTS takes a SHARE lock on the table
# even when the index exists, which conflicts with writers, and migrate() runs
# on every command start; so each runs only while pg_indexes lacks the index.
# The statements still say IF NOT EXISTS: two first starts can both see the
# index missing, and the loser must not fail.
_INDEXES = [
    ("candidate_log_index",
     "CREATE INDEX IF NOT EXISTS candidate_log_index ON candidate (log_id, log_index)"),
    ("raw_batch_created_at",
     "CREATE INDEX IF NOT EXISTS raw_batch_created_at ON raw_batch (created_at)"),
    ("raw_batch_blob_sha256",
     "CREATE INDEX IF NOT EXISTS raw_batch_blob_sha256 ON raw_batch (blob_sha256)"),
    ("candidate_fqdn", "CREATE INDEX IF NOT EXISTS candidate_fqdn ON candidate (fqdn)"),
    ("fetch_job_open_fqdn",
     "CREATE UNIQUE INDEX IF NOT EXISTS fetch_job_open_fqdn ON fetch_job (fqdn) WHERE state = 'open'"),
    ("fetch_job_due",
     "CREATE INDEX IF NOT EXISTS fetch_job_due ON fetch_job (priority DESC, due_at DESC) "
     "WHERE state = 'open'"),
    ("fetch_job_fqdn", "CREATE INDEX IF NOT EXISTS fetch_job_fqdn ON fetch_job (fqdn)"),
]

# Changes to tables that may predate stage two, as (table, column, change, DDL).
# ALTER TABLE takes ACCESS EXCLUSIVE even when IF NOT EXISTS makes it a no-op,
# and migrate() runs on every command start, so each one runs only while
# information_schema shows it is still needed: "add" while the column is
# missing, "drop_not_null" while it is NOT NULL.
_UPGRADES = [
    ("candidate", "reason", "add",
     "ALTER TABLE candidate ADD COLUMN IF NOT EXISTS reason text NOT NULL DEFAULT 'first_seen'"),
    ("candidate", "log_id", "drop_not_null",
     "ALTER TABLE candidate ALTER COLUMN log_id DROP NOT NULL"),
    ("candidate", "log_index", "drop_not_null",
     "ALTER TABLE candidate ALTER COLUMN log_index DROP NOT NULL"),
    ("candidate", "cert_key", "drop_not_null",
     "ALTER TABLE candidate ALTER COLUMN cert_key DROP NOT NULL"),
    ("candidate", "first_seen_ms", "drop_not_null",
     "ALTER TABLE candidate ALTER COLUMN first_seen_ms DROP NOT NULL"),
    ("ingest_stat", "candidates_recheck", "add",
     "ALTER TABLE ingest_stat ADD COLUMN IF NOT EXISTS candidates_recheck bigint NOT NULL DEFAULT 0"),
]

STAT_COLUMNS = (
    "entries",
    "bytes",
    "parse_failed",
    "certs_unique",
    "fqdns_new",
    "suppressed",  # total; the supp_* columns split it by reason
    "supp_tranco",
    "supp_public_apex",
    "supp_wildcard",
    "candidates",
    "candidates_recheck",
)


@dataclass(frozen=True)
class CandidateRow:
    fqdn: str
    registrable: str
    log_id: str | None
    log_index: int | None
    cert_key: bytes | None
    first_seen_ms: int | None
    reason: str = "first_seen"


async def connect(url: str) -> psycopg.AsyncConnection:
    return await psycopg.AsyncConnection.connect(url, autocommit=False)


async def migrate(conn: psycopg.AsyncConnection) -> None:
    for stmt in _SCHEMA:
        await conn.execute(stmt)
    for table, column, change, stmt in _UPGRADES:
        cur = await conn.execute(
            """SELECT is_nullable FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = %s AND column_name = %s""",
            (table, column),
        )
        row = await cur.fetchone()
        if change == "add":
            needed = row is None
        else:
            needed = row is not None and row[0] == "NO"
        if needed:
            await conn.execute(stmt)
    cur = await conn.execute(
        "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()"
    )
    existing = {r[0] for r in await cur.fetchall()}
    for name, stmt in _INDEXES:
        if name not in existing:
            await conn.execute(stmt)
    await conn.commit()


async def get_cursor(conn: psycopg.AsyncConnection, log_id: str) -> int | None:
    """The log's next index, or None if the log has no cursor row yet."""
    cur = await conn.execute(
        "SELECT next_index FROM log_cursor WHERE log_id = %s", (log_id,)
    )
    row = await cur.fetchone()
    return None if row is None else row[0]


async def set_cursor(conn: psycopg.AsyncConnection, log_id: str, next_index: int) -> None:
    await conn.execute(
        """INSERT INTO log_cursor (log_id, next_index)
           VALUES (%s, %s)
           ON CONFLICT (log_id) DO UPDATE SET
             next_index = EXCLUDED.next_index,
             updated_at = now()""",
        (log_id, next_index),
    )


async def init_cursor(
    conn: psycopg.AsyncConnection, log_id: str, next_index: int
) -> bool:
    """Create the log's cursor row; True if created, False if one already exists.

    Unlike ``set_cursor`` this never overwrites, so a log's first cursor cannot
    clobber one written by another process in the meantime.
    """
    cur = await conn.execute(
        """INSERT INTO log_cursor (log_id, next_index) VALUES (%s, %s)
           ON CONFLICT (log_id) DO NOTHING""",
        (log_id, next_index),
    )
    return cur.rowcount == 1


async def add_candidates(
    conn: psycopg.AsyncConnection, rows: list[CandidateRow]
) -> None:
    # Concurrent log tasks insert the same names (one certificate reaches
    # several logs), and fetch_job's unique open-fqdn index makes them wait on
    # each other. Inserting in one global order (by fqdn) rules out deadlocks.
    rows = sorted(rows, key=lambda r: r.fqdn)
    async with conn.cursor() as cur:
        await cur.executemany(
            """WITH c AS (
                 INSERT INTO candidate
                   (fqdn, registrable, log_id, log_index, cert_key, first_seen_ms, reason)
                 VALUES (%s, %s, %s, %s, %s, %s, %s)
                 RETURNING id, fqdn, registrable, created_at)
               INSERT INTO fetch_job (candidate_id, fqdn, registrable, due_at)
               SELECT id, fqdn, registrable, created_at FROM c
               ON CONFLICT (fqdn) WHERE state = 'open' DO NOTHING""",
            [
                (r.fqdn, r.registrable, r.log_id, r.log_index, r.cert_key, r.first_seen_ms, r.reason)
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
    """Add ``increments`` to the (log_id, day) row.

    With no increments this does nothing, and in particular creates no row:
    ``read_stat`` reports zeros for an absent row anyway.
    """
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
    """Counts for one log and day (zeros if there is no row)."""
    cols = ", ".join(STAT_COLUMNS)
    cur = await conn.execute(
        f"SELECT {cols} FROM ingest_stat WHERE log_id = %s AND day = %s",
        (log_id, day),
    )
    row = await cur.fetchone()
    return dict(zip(STAT_COLUMNS, row or (0,) * len(STAT_COLUMNS)))


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
        try:
            path = bs.path(sha)
        except ValueError:
            _log.warning("raw_batch row holds an invalid blob digest %r; not unlinking", sha)
            continue
        try:
            os.chmod(path, 0o644)
            path.unlink()
        except FileNotFoundError:
            pass
    return count
