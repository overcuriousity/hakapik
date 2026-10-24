import asyncio
import dataclasses
import hashlib
import json
import os

import psycopg
import pytest

import hakapik.store as store
from hakapik.asn import AsnDb
from hakapik.blobstore import BlobStore
from hakapik.db import CandidateRow, add_candidates, add_raw_batch, connect
from hakapik.jobs import enqueue_manual
from hakapik.protocol import (
    AttemptResult,
    BlobRef,
    DnsAnswer,
    NodeKey,
    PageResult,
    open_envelope,
    seal,
)
from hakapik.store import ResultRejected, register_node, store_result, write_manifest

LADDER = (0, 120, 600)
T0 = "2026-10-24T10:00:00Z"
T1 = "2026-10-24T10:00:05Z"


async def _count(conn, table, where="true", params=()):
    cur = await conn.execute(f"SELECT count(*) FROM {table} WHERE {where}", params)
    return (await cur.fetchone())[0]


async def _job(conn, fqdn="a.example.com"):
    await enqueue_manual(conn, [fqdn])
    cur = await conn.execute(
        "SELECT id, candidate_id FROM fetch_job WHERE fqdn = %s", (fqdn,))
    return await cur.fetchone()


def _result(bs, key, job_id, step, refs=None):
    if refs is None:
        warc = b"WARC/1.1\r\n" + bytes([step])
        png = b"\x89PNG" + bytes([step])
        refs = (
            BlobRef("mobile", "warc", bs.put(warc, "application/warc"), len(warc),
                    "application/warc"),
            BlobRef("mobile", "screenshot", bs.put(png, "image/png"), len(png),
                    "image/png"),
        )
    return AttemptResult(
        job_id=job_id, step=step, node_id=key.node_id, egress_address="192.0.2.1",
        started_at=T0, finished_at=T1, outcome="live", error=None,
        dns=(
            DnsAnswer("a.example.com", "A", "NOERROR", 300, ("192.0.2.7",),
                      "system", T0),
            DnsAnswer("a.example.com", "AAAA", "NOERROR", None, (), "system", T0),
        ),
        pages=(
            PageResult("mobile", "live", 200, "https://a.example.com/login",
                       "192.0.2.7", (), None, T0, T1),
            PageResult("desktop", "live", 302, "https://a.example.com/other",
                       "192.0.2.7", (), None, T0, T1),
        ),
        blobs=refs,
    )


@pytest.fixture
def key():
    return NodeKey(b"\x01" * 32)


async def _setup(conn, tmp_path, key):
    bs = BlobStore(tmp_path / "blobs")
    await register_node(conn, key.node_id, key.public_key)
    jid, cid = await _job(conn)
    return bs, jid, cid


async def _manifest(conn, bs, cid, version):
    cur = await conn.execute(
        "SELECT sha256, prev_sha256 FROM manifest WHERE candidate_id = %s AND version = %s",
        (cid, version))
    sha, prev = await cur.fetchone()
    data = bs.path(sha).read_bytes()
    assert hashlib.sha256(data).hexdigest() == sha
    return sha, prev, json.loads(data)


async def _nothing_written(conn):
    for t in ("attempt", "blob", "dns_answer", "artifact", "manifest"):
        assert await _count(conn, t) == 0, t
    assert await _count(conn, "fetch_job", "step = 0 AND state = 'open'") == 1


async def test_store_writes_attempt_dns_artifacts_manifest(conn, tmp_path, key):
    bs, jid, cid = await _setup(conn, tmp_path, key)
    r = _result(bs, key, jid, 0)
    env = seal(r, key)
    aid = await store_result(conn, bs, env, LADDER)
    assert aid is not None
    cur = await conn.execute(
        "SELECT outcome, http_status, final_url, node_id, envelope_sha256, started_at "
        "FROM attempt WHERE id = %s", (aid,))
    outcome, status, url, node, env_sha, started = await cur.fetchone()
    assert (outcome, status, url, node) == ("live", 200, "https://a.example.com/login",
                                           key.node_id)
    assert env_sha == hashlib.sha256(env).hexdigest()
    assert bs.path(env_sha).read_bytes() == env
    assert started.isoformat().startswith("2026-10-24")
    assert await _count(conn, "dns_answer", "attempt_id = %s", (aid,)) == len(r.dns)
    cur = await conn.execute(
        "SELECT profile, kind, sha256 FROM artifact WHERE attempt_id = %s ORDER BY id",
        (aid,))
    assert await cur.fetchall() == [(b.profile, b.kind, b.sha256) for b in r.blobs]
    assert await _count(conn, "blob") == 4  # envelope, two refs, manifest
    cur = await conn.execute(
        "SELECT media_type FROM blob WHERE sha256 = %s", (env_sha,))
    assert (await cur.fetchone())[0] == "application/json"
    assert await _count(conn, "fetch_job", "id = %s AND step = 1", (jid,)) == 1
    _, prev, doc = await _manifest(conn, bs, cid, 1)
    assert prev is None and doc["version"] == 1 and doc["prev"] is None
    assert doc["candidate"]["id"] == cid and doc["ct_raw_batch"] is None
    [a] = doc["attempts"]
    assert a["attempt_id"] == aid and a["envelope_sha256"] == env_sha
    assert [b["sha256"] for b in a["blobs"]] == [b.sha256 for b in r.blobs]


async def test_duplicate_envelope_is_noop(conn, tmp_path, key):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    env = seal(_result(bs, key, jid, 0), key)
    assert await store_result(conn, bs, env, LADDER) is not None
    # Stale path: the job has moved on to step 1.
    assert await store_result(conn, bs, env, LADDER) is None
    assert await _count(conn, "attempt") == 1
    # Conflict path: the job is back at step 0, but UNIQUE(job_id, step) holds.
    await conn.execute("UPDATE fetch_job SET step = 0 WHERE id = %s", (jid,))
    assert await store_result(conn, bs, env, LADDER) is None
    assert await _count(conn, "attempt") == 1
    assert await _count(conn, "manifest") == 1


async def test_stale_step_is_noop(conn, tmp_path, key):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    assert await store_result(conn, bs, seal(_result(bs, key, jid, 1), key), LADDER) is None
    await _nothing_written(conn)


async def test_closed_or_unknown_job_is_noop(conn, tmp_path, key):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    assert await store_result(conn, bs, seal(_result(bs, key, jid + 99, 0), key),
                              LADDER) is None
    await conn.execute("UPDATE fetch_job SET state = 'aged_out'")
    assert await store_result(conn, bs, seal(_result(bs, key, jid, 0), key), LADDER) is None
    for t in ("attempt", "blob", "manifest"):
        assert await _count(conn, t) == 0


async def test_rejects_bad_signature(conn, tmp_path, key):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    env = json.loads(seal(_result(bs, key, jid, 0), key))
    other = seal(_result(bs, key, jid, 1), key)
    env["signature"] = json.loads(other)["signature"]
    with pytest.raises(ResultRejected):
        await store_result(conn, bs, json.dumps(env).encode(), LADDER)
    await _nothing_written(conn)


async def test_rejects_unregistered_node(conn, tmp_path, key):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    stranger = NodeKey(b"\x02" * 32)
    r = _result(bs, stranger, jid, 0)
    with pytest.raises(ResultRejected):
        await store_result(conn, bs, seal(r, stranger), LADDER)
    await _nothing_written(conn)


async def test_rejects_garbage_envelope(conn, tmp_path, key):
    bs, _, _ = await _setup(conn, tmp_path, key)
    with pytest.raises(ResultRejected):
        await store_result(conn, bs, b"not json", LADDER)
    await _nothing_written(conn)


async def test_rejects_blob_hash_mismatch(conn, tmp_path, key):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    missing = BlobRef("mobile", "warc", "ab" * 32, 3, "application/warc")
    with pytest.raises(ResultRejected):
        await store_result(conn, bs, seal(_result(bs, key, jid, 0, (missing,)), key), LADDER)
    await _nothing_written(conn)


async def test_rejects_blob_size_mismatch(conn, tmp_path, key):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    sha = bs.put(b"abc", "text/plain")
    wrong = BlobRef("mobile", "dom", sha, 4, "text/html")
    with pytest.raises(ResultRejected):
        await store_result(conn, bs, seal(_result(bs, key, jid, 0, (wrong,)), key), LADDER)
    await _nothing_written(conn)


async def test_rejects_blob_content_mismatch(conn, tmp_path, key):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    sha = bs.put(b"abc", "text/plain")
    path = bs.path(sha)
    path.chmod(0o644)
    path.write_bytes(b"abd")
    wrong = BlobRef("mobile", "dom", sha, 3, "text/html")
    with pytest.raises(ResultRejected):
        await store_result(conn, bs, seal(_result(bs, key, jid, 0, (wrong,)), key), LADDER)
    await _nothing_written(conn)


async def test_rejects_bad_digest_string(conn, tmp_path, key):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    bad = BlobRef("mobile", "dom", "../../etc/passwd", 3, "text/html")
    with pytest.raises(ResultRejected):
        await store_result(conn, bs, seal(_result(bs, key, jid, 0, (bad,)), key), LADDER)
    await _nothing_written(conn)


async def test_manifest_chain(conn, tmp_path, key):
    bs, jid, cid = await _setup(conn, tmp_path, key)
    a0 = await store_result(conn, bs, seal(_result(bs, key, jid, 0), key), LADDER)
    a1 = await store_result(conn, bs, seal(_result(bs, key, jid, 1), key), LADDER)
    sha1, prev1, doc1 = await _manifest(conn, bs, cid, 1)
    sha2, prev2, doc2 = await _manifest(conn, bs, cid, 2)
    assert prev1 is None and prev2 == sha1 and doc2["prev"] == sha1
    assert doc2["version"] == 2
    assert [(a["attempt_id"], a["step"]) for a in doc2["attempts"]] == [(a0, 0), (a1, 1)]


async def test_manifest_is_deterministic(conn, tmp_path, key):
    # The same database state gives the same bytes, whatever the session time
    # zone: each write is rolled back, so both see the same version and prev.
    bs, jid, cid = await _setup(conn, tmp_path, key)
    await store_result(conn, bs, seal(_result(bs, key, jid, 0), key), LADDER)
    shas = []
    for tz in ("UTC", "Asia/Tokyo"):
        async with conn.transaction():  # psycopg.Rollback leaves it quietly
            await conn.execute(f"SET LOCAL TimeZone = '{tz}'")
            shas.append(await write_manifest(conn, bs, cid))
            raise psycopg.Rollback()
    assert shas[0] == shas[1]
    data = bs.path(shas[0]).read_bytes()
    doc = json.loads(data)
    assert doc["version"] == 2
    assert data == json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


async def test_manifest_ct_provenance(conn, tmp_path):
    bs = BlobStore(tmp_path / "blobs")
    await add_candidates(conn, [CandidateRow("b.example.com", "example.com", "log1", 42,
                                             b"\xca\xfe", 1700000000000)])
    await add_raw_batch(conn, "log1", 0, 9, "11" * 32, 10, 100)
    await add_raw_batch(conn, "log1", 40, 49, "22" * 32, 10, 100)
    cur = await conn.execute("SELECT id FROM candidate")
    cid = (await cur.fetchone())[0]
    sha = await write_manifest(conn, bs, cid)
    doc = json.loads(bs.path(sha).read_bytes())
    assert doc["ct_raw_batch"] == "22" * 32
    assert doc["candidate"]["cert_key"] == "cafe"
    assert doc["candidate"]["log_index"] == 42 and doc["attempts"] == []


async def test_register_node_conflicting_key_raises(conn, key):
    await register_node(conn, key.node_id, key.public_key)
    await register_node(conn, key.node_id, key.public_key)
    assert await _count(conn, "node") == 1
    with pytest.raises(ValueError):
        await register_node(conn, key.node_id, NodeKey(b"\x02" * 32).public_key)


@pytest.fixture
def asn_db(asn_mmdb, tmp_path):
    return lambda bs: AsnDb.load(asn_mmdb("192.0.2.0/24"), bs)


async def test_store_records_asn(conn, tmp_path, key, asn_db):
    bs, jid, cid = await _setup(conn, tmp_path, key)
    db = asn_db(bs)
    aid = await store_result(conn, bs, seal(_result(bs, key, jid, 0), key), LADDER,
                             asn_db=db)
    cur = await conn.execute(
        "SELECT asn, asn_org, asn_db_sha256 FROM attempt WHERE id = %s", (aid,))
    assert await cur.fetchone() == (64500, "Example AS", db.sha256)
    cur = await conn.execute(
        "SELECT media_type FROM blob WHERE sha256 = %s", (db.sha256,))
    assert (await cur.fetchone())[0] == "application/vnd.maxmind.mmdb"
    _, _, doc = await _manifest(conn, bs, cid, 1)
    [a] = doc["attempts"]
    assert (a["asn"], a["asn_org"], a["asn_db_sha256"]) == (64500, "Example AS", db.sha256)
    assert a["asn_db"] == {"sha256": db.sha256, "size": db.size,
                           "media_type": "application/vnd.maxmind.mmdb"}


async def test_store_asn_falls_back_to_dns_address(conn, tmp_path, key, asn_db):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    db = asn_db(bs)
    r = _result(bs, key, jid, 0)
    r = dataclasses.replace(r, pages=tuple(
        dataclasses.replace(p, server_ip=None) for p in r.pages))
    aid = await store_result(conn, bs, seal(r, key), LADDER, asn_db=db)
    cur = await conn.execute("SELECT asn FROM attempt WHERE id = %s", (aid,))
    assert (await cur.fetchone())[0] == 64500


async def test_store_without_asn_db_leaves_nulls(conn, tmp_path, key):
    bs, jid, cid = await _setup(conn, tmp_path, key)
    aid = await store_result(conn, bs, seal(_result(bs, key, jid, 0), key), LADDER)
    cur = await conn.execute(
        "SELECT asn, asn_org, asn_db_sha256 FROM attempt WHERE id = %s", (aid,))
    assert await cur.fetchone() == (None, None, None)
    _, _, doc = await _manifest(conn, bs, cid, 1)
    [a] = doc["attempts"]
    assert (a["asn"], a["asn_org"], a["asn_db_sha256"], a["asn_db"]) == (None,) * 4


async def test_store_miss_records_snapshot_hash(conn, tmp_path, key, asn_db):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    db = asn_db(bs)
    r = _result(bs, key, jid, 0)
    r = dataclasses.replace(r, pages=tuple(
        dataclasses.replace(p, server_ip="8.8.8.8") for p in r.pages))
    aid = await store_result(conn, bs, seal(r, key), LADDER, asn_db=db)
    cur = await conn.execute(
        "SELECT asn, asn_org, asn_db_sha256 FROM attempt WHERE id = %s", (aid,))
    assert await cur.fetchone() == (None, None, db.sha256)
    assert await _count(conn, "blob", "sha256 = %s", (db.sha256,)) == 1


async def test_store_no_address_leaves_nulls_even_with_db(conn, tmp_path, key, asn_db):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    db = asn_db(bs)
    r = _result(bs, key, jid, 0)
    r = dataclasses.replace(
        r, dns=(), pages=tuple(dataclasses.replace(p, server_ip=None) for p in r.pages))
    aid = await store_result(conn, bs, seal(r, key), LADDER, asn_db=db)
    cur = await conn.execute(
        "SELECT asn, asn_org, asn_db_sha256 FROM attempt WHERE id = %s", (aid,))
    assert await cur.fetchone() == (None, None, None)
    assert await _count(conn, "blob", "sha256 = %s", (db.sha256,)) == 0


async def test_concurrent_store_of_same_step_waits_then_is_noop(conn, tmp_path, key):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    await conn.commit()
    env_a = seal(_result(bs, key, jid, 0), key)
    env_b = seal(dataclasses.replace(_result(bs, key, jid, 0), error="other"), key)
    other = await connect(os.environ["HAKAPIK_TEST_DB"])
    try:
        assert await store_result(conn, bs, env_a, LADDER) is not None
        task = asyncio.create_task(store_result(other, bs, env_b, LADDER))
        await asyncio.sleep(0.3)
        assert not task.done()  # blocked on the job row
        await conn.commit()
        assert await task is None
        await other.commit()
    finally:
        await other.close()
    assert await _count(conn, "attempt") == 1
    assert await _count(conn, "blob", "sha256 = %s",
                        (hashlib.sha256(env_b).hexdigest(),)) == 0


async def test_store_locks_every_blob_in_order_before_verifying(conn, tmp_path, key, monkeypatch):
    # The orphan sweep must not unlink a listed blob between its verification
    # and the commit; blob locks come before the job row lock, sorted.
    bs, jid, cid = await _setup(conn, tmp_path, key)
    r = _result(bs, key, jid, 0)
    env = seal(r, key)
    events = []
    real_lock, real_verify = store.lock_blob, store._verify_blob

    async def lock(c, sha):
        events.append(("lock", sha))
        await real_lock(c, sha)

    def verify(bs_, sha, size):
        events.append(("verify", sha))
        real_verify(bs_, sha, size)

    monkeypatch.setattr(store, "lock_blob", lock)
    monkeypatch.setattr(store, "_verify_blob", verify)
    assert await store_result(conn, bs, env, LADDER) is not None
    locks = [sha for kind, sha in events if kind == "lock"]
    expected = sorted({hashlib.sha256(env).hexdigest(), *(b.sha256 for b in r.blobs)})
    assert locks == expected
    first_verify = next(i for i, e in enumerate(events) if e[0] == "verify")
    assert all(e[0] == "lock" for e in events[:first_verify])
    assert len(locks) == first_verify


@pytest.mark.parametrize("field,value", [
    ("started_at", "yesterday"), ("finished_at", "2026-10-24T10:00:05"),
    ("dns", "not a time"), ("dns", "2026-10-24T10:00:00"),
])
async def test_rejects_bad_or_naive_timestamps(conn, tmp_path, key, field, value):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    r = _result(bs, key, jid, 0)
    if field == "dns":
        r = dataclasses.replace(r, dns=(dataclasses.replace(r.dns[0], queried_at=value),))
    else:
        r = dataclasses.replace(r, **{field: value})
    with pytest.raises(ResultRejected, match="timestamp"):
        await store_result(conn, bs, seal(r, key), LADDER)
    await _nothing_written(conn)


async def test_blob_size_is_checked_before_reading(conn, tmp_path, key, monkeypatch):
    bs, jid, _ = await _setup(conn, tmp_path, key)
    sha = bs.put(b"abc" * 1000, "text/plain")
    wrong = BlobRef("mobile", "dom", sha, 4, "text/html")

    def no_read(*a, **k):
        raise AssertionError("blob opened despite a size mismatch")

    monkeypatch.setattr(store, "open", no_read, raising=False)
    with pytest.raises(ResultRejected, match="size"):
        await store_result(conn, bs, seal(_result(bs, key, jid, 0, (wrong,)), key), LADDER)
    await _nothing_written(conn)


async def test_manifest_alone_verifies_every_envelope(conn, tmp_path, key):
    # Each attempt names its node's public key, so the manifest and the blobs
    # suffice to check every envelope signature, without the database.
    bs, jid, cid = await _setup(conn, tmp_path, key)
    await store_result(conn, bs, seal(_result(bs, key, jid, 0), key), LADDER)
    await store_result(conn, bs, seal(_result(bs, key, jid, 1), key), LADDER)
    _, _, doc = await _manifest(conn, bs, cid, 2)
    assert len(doc["attempts"]) == 2
    for a in doc["attempts"]:
        assert a["node_public_key"] == key.public_key.hex()
        pub = bytes.fromhex(a["node_public_key"])
        env = bs.path(a["envelope_sha256"]).read_bytes()
        r = open_envelope(env, {a["node_id"]: pub}.get)
        assert (r.job_id, r.step) == (jid, a["step"])
