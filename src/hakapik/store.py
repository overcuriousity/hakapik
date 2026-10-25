"""Head-side verified result store and per-candidate manifest chain.

The head never trusts a worker result: the signature is checked against the
registered node key and every listed blob is re-hashed before anything is
written. Then the attempt, its DNS answers and artefacts, the job advance and
a new hash-chained manifest version for the candidate land in the caller's
transaction. No function here commits.
"""

import hashlib
import json
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row

from hakapik.asn import MMDB_MEDIA_TYPE, AsnDb
from hakapik.blobstore import BlobStore
from hakapik.db import lock_blob
from hakapik.jobs import advance_job
from hakapik.protocol import BadEnvelope, canonical_json, open_envelope
from hakapik.resolve import addresses


class ResultRejected(Exception):
    pass


async def register_node(
    conn: psycopg.AsyncConnection, node_id: str, public_key: bytes
) -> None:
    """Register a worker key; the same key again is a no-op, a different one raises."""
    await conn.execute(
        "INSERT INTO node (node_id, public_key) VALUES (%s, %s) ON CONFLICT DO NOTHING",
        (node_id, public_key),
    )
    cur = await conn.execute("SELECT public_key FROM node WHERE node_id = %s", (node_id,))
    if bytes((await cur.fetchone())[0]) != public_key:
        raise ValueError(f"node {node_id} is registered with a different key")


def _envelope_node_id(envelope: bytes) -> str | None:
    try:
        node_id = json.loads(envelope)["node_id"]
    except (ValueError, KeyError, TypeError, RecursionError):
        return None
    return node_id if isinstance(node_id, str) else None


def _ts(s: str) -> datetime:
    try:
        t = datetime.fromisoformat(s)
    except (ValueError, TypeError) as e:
        raise ResultRejected(f"bad timestamp {s!r}") from e
    if t.tzinfo is None:
        raise ResultRejected(f"timestamp without offset {s!r}")
    return t


def _verify_blob(bs: BlobStore, sha256: str, size: int) -> None:
    try:
        path = bs.path(sha256)
    except ValueError as e:
        raise ResultRejected(str(e)) from e
    h, n = hashlib.sha256(), 0
    try:
        # Size first: a wrong size is rejected without reading the file.
        if path.stat().st_size != size:
            raise ResultRejected(f"blob {sha256} does not match its size")
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                h.update(chunk)
                n += len(chunk)
    except FileNotFoundError as e:
        raise ResultRejected(f"blob {sha256} not in store") from e
    if h.hexdigest() != sha256 or n != size:
        raise ResultRejected(f"blob {sha256} does not match its hash or size")


async def store_result(
    conn: psycopg.AsyncConnection, bs: BlobStore, envelope: bytes,
    ladder: tuple[int, ...], *, asn_db: AsnDb | None = None,
) -> int | None:
    """Verify and store a sealed result; the attempt id, or None if stale or duplicate.

    With ``asn_db`` the attempt also records the ASN of the mobile page's server
    address (or, failing that, the first resolved address) and the snapshot hash.

    Every check runs before the first write, so a rejected or stale result
    leaves the database unchanged.
    """
    # open_envelope needs a synchronous key lookup, so the key is fetched first.
    # That parses the envelope JSON twice (here and in open_envelope); it is a
    # few hundred bytes plus a base64 payload, cheaper than a second API.
    pub = None
    node_id = _envelope_node_id(envelope)
    if node_id is not None:
        cur = await conn.execute("SELECT public_key FROM node WHERE node_id = %s", (node_id,))
        row = await cur.fetchone()
        pub = None if row is None else bytes(row[0])
    try:
        r = open_envelope(envelope, lambda nid: pub if nid == node_id else None)
    except BadEnvelope as e:
        raise ResultRejected(str(e)) from e

    # Blob locks first (db.lock_blob, sorted by digest): the orphan sweep
    # cannot unlink a listed blob between its verification below and the
    # commit of the rows referencing it. Every writer takes its blob locks
    # before any row lock (ingest takes one, before its inserts), so blob and
    # row locks cannot form a cycle. (Two digests sharing a 64-bit lock key
    # could still order differently; Postgres then reports a deadlock and the
    # job is retried after its lease, nothing hangs.) The manifest blob of
    # write_manifest needs no lock: its bytes hold the candidate id and the
    # new attempt's id, which comes from a sequence and is never reused, even
    # after a rollback; so no earlier put wrote these bytes, and the file is
    # new and young.
    env_sha = hashlib.sha256(envelope).hexdigest()
    for sha in sorted({env_sha, *(b.sha256 for b in r.blobs)}):
        await lock_blob(conn, sha)

    # FOR UPDATE: a concurrent store of the same (job_id, step) waits here,
    # then sees the advanced step and returns None before writing anything.
    # Lock order is blobs, job, then candidate (write_manifest).
    cur = await conn.execute(
        "SELECT candidate_id, fqdn FROM fetch_job WHERE id = %s AND step = %s AND state = 'open' "
        "FOR UPDATE",
        (r.job_id, r.step),
    )
    row = await cur.fetchone()
    if row is None:
        return None
    candidate_id, fqdn = row

    started, finished = _ts(r.started_at), _ts(r.finished_at)
    queried = [_ts(d.queried_at) for d in r.dns]
    for b in r.blobs:
        _verify_blob(bs, b.sha256, b.size)

    bs.put(envelope, "application/json")
    blob_rows = [(env_sha, len(envelope), "application/json")]
    blob_rows += [(b.sha256, b.size, b.media_type) for b in r.blobs]
    async with conn.cursor() as c:
        await c.executemany(
            "INSERT INTO blob (sha256, size, media_type) VALUES (%s, %s, %s) "
            "ON CONFLICT DO NOTHING",
            blob_rows,
        )

    mobile = next((p for p in r.pages if p.profile == "mobile"), None)
    hit = snapshot = None
    if asn_db is not None:
        ip = (mobile.server_ip if mobile else None) or next(iter(addresses(r.dns, fqdn)), None)
        if ip:
            hit = asn_db.lookup(ip)
            snapshot = asn_db.sha256
            await conn.execute(
                "INSERT INTO blob (sha256, size, media_type) VALUES (%s, %s, %s) "
                "ON CONFLICT DO NOTHING",
                (asn_db.sha256, asn_db.size, MMDB_MEDIA_TYPE),
            )
    cur = await conn.execute(
        """INSERT INTO attempt (job_id, step, node_id, egress_address, started_at,
             finished_at, outcome, http_status, final_url, error, envelope_sha256,
             asn, asn_org, asn_db_sha256)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT (job_id, step) DO NOTHING RETURNING id""",
        (r.job_id, r.step, r.node_id, r.egress_address, started, finished, r.outcome,
         mobile.http_status if mobile else None,
         mobile.final_url if mobile else None, r.error, env_sha,
         hit and hit.asn, hit and hit.org, snapshot),
    )
    row = await cur.fetchone()
    if row is None:
        return None
    attempt_id = row[0]

    async with conn.cursor() as c:
        if r.dns:
            await c.executemany(
                """INSERT INTO dns_answer (attempt_id, node_id, qname, rrtype, rcode,
                     ttl, answers, resolver, queried_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                [(attempt_id, r.node_id, d.qname, d.rrtype, d.rcode, d.ttl,
                  list(d.answers), d.resolver, q) for d, q in zip(r.dns, queried)],
            )
        if r.blobs:
            await c.executemany(
                "INSERT INTO artifact (attempt_id, profile, kind, sha256) "
                "VALUES (%s, %s, %s, %s)",
                [(attempt_id, b.profile, b.kind, b.sha256) for b in r.blobs],
            )
    await advance_job(conn, r.job_id, r.step, ladder)
    await write_manifest(conn, bs, candidate_id)
    return attempt_id


def _plain(v):
    if isinstance(v, (bytes, memoryview)):
        return bytes(v).hex()
    if isinstance(v, datetime):
        # UTC, so the bytes do not depend on the session time zone.
        return v.astimezone(timezone.utc).isoformat()
    return v


async def write_manifest(
    conn: psycopg.AsyncConnection, bs: BlobStore, candidate_id: int
) -> str:
    """Issue the candidate's next manifest version; returns its sha256."""
    async with conn.cursor(row_factory=dict_row) as cur:
        # FOR UPDATE on the candidate row serialises manifest writers for this
        # candidate, so version and prev below cannot race.
        await cur.execute("SELECT * FROM candidate WHERE id = %s FOR UPDATE", (candidate_id,))
        cand = await cur.fetchone()
        if cand is None:
            raise ValueError(f"no candidate {candidate_id}")
        candidate = {k: _plain(v) for k, v in cand.items()}

        ct_raw_batch = None
        if cand["log_id"] is not None and cand["log_index"] is not None:
            await cur.execute(
                """SELECT blob_sha256 FROM raw_batch
                   WHERE log_id = %s AND %s BETWEEN start_index AND end_index
                   ORDER BY id LIMIT 1""",
                (cand["log_id"], cand["log_index"]),
            )
            row = await cur.fetchone()
            ct_raw_batch = row and row["blob_sha256"]

        await cur.execute(
            """SELECT a.id, a.step, a.node_id, n.public_key, a.outcome, a.started_at,
                      a.envelope_sha256, a.asn, a.asn_org, a.asn_db_sha256,
                      b.size AS asn_db_size, b.media_type AS asn_db_media_type
               FROM attempt a JOIN fetch_job j ON j.id = a.job_id
               JOIN node n ON n.node_id = a.node_id
               LEFT JOIN blob b ON b.sha256 = a.asn_db_sha256
               WHERE j.candidate_id = %s ORDER BY a.step, a.id""",
            (candidate_id,),
        )
        attempts = [
            # The signing node's Ed25519 public key (hex): with it the
            # manifest alone lets an auditor verify each envelope (spec 8).
            {"attempt_id": a["id"], "step": a["step"], "node_id": a["node_id"],
             "node_public_key": _plain(a["public_key"]),
             "outcome": a["outcome"], "started_at": _plain(a["started_at"]),
             "envelope_sha256": a["envelope_sha256"],
             "asn": a["asn"], "asn_org": a["asn_org"],
             "asn_db_sha256": a["asn_db_sha256"],
             "asn_db": a["asn_db_sha256"] and {
                 "sha256": a["asn_db_sha256"], "size": a["asn_db_size"],
                 "media_type": a["asn_db_media_type"]},
             "blobs": []}
            for a in await cur.fetchall()
        ]
        by_id = {a["attempt_id"]: a for a in attempts}
        if by_id:
            await cur.execute(
                """SELECT r.attempt_id, r.profile, r.kind, r.sha256, b.size, b.media_type
                   FROM artifact r JOIN blob b ON b.sha256 = r.sha256
                   WHERE r.attempt_id = ANY(%s) ORDER BY r.id""",
                (list(by_id),),
            )
            for b in await cur.fetchall():
                by_id[b.pop("attempt_id")]["blobs"].append(b)

        await cur.execute(
            """SELECT version, sha256 FROM manifest WHERE candidate_id = %s
               ORDER BY version DESC LIMIT 1""",
            (candidate_id,),
        )
        last = await cur.fetchone()
    version = 1 if last is None else last["version"] + 1
    prev = None if last is None else last["sha256"]

    doc = canonical_json({
        "version": version, "prev": prev, "candidate": candidate,
        "ct_raw_batch": ct_raw_batch, "attempts": attempts,
    })
    sha = bs.put(doc, "application/json")
    await conn.execute(
        "INSERT INTO blob (sha256, size, media_type) VALUES (%s, %s, 'application/json') "
        "ON CONFLICT DO NOTHING",
        (sha, len(doc)),
    )
    await conn.execute(
        "INSERT INTO manifest (candidate_id, version, sha256, prev_sha256) "
        "VALUES (%s, %s, %s, %s)",
        (candidate_id, version, sha, prev),
    )
    return sha
