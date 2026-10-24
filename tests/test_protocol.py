import base64
import errno
import json
import os
import threading

import pytest

import hakapik.protocol as protocol
from hakapik.protocol import (
    OUTCOMES,
    AttemptResult,
    BadEnvelope,
    BlobRef,
    DnsAnswer,
    Job,
    NodeKey,
    PageResult,
    canonical_json,
    open_envelope,
    result_from_json,
    result_to_json,
    seal,
)


def _result(node_id="n" * 32):
    return AttemptResult(
        job_id=7, step=1, node_id=node_id, egress_address="192.0.2.1",
        started_at="2026-10-24T10:00:00Z", finished_at="2026-10-24T10:00:05Z",
        outcome="live", error=None,
        dns=(DnsAnswer("a.example", "A", "NOERROR", 300, ("192.0.2.9",), "system",
                       "2026-10-24T10:00:00Z"),
             DnsAnswer("a.example", "AAAA", "NXDOMAIN", None, (), "system",
                       "2026-10-24T10:00:01Z")),
        pages=(PageResult("mobile", "live", 200, "https://a.example/x", "192.0.2.9",
                          ("https://a.example/",), None,
                          "2026-10-24T10:00:02Z", "2026-10-24T10:00:04Z"),),
        blobs=(BlobRef("mobile", "dom", "a" * 64, 12, "text/html"),),
    )


def _env(tmp_path, **kw):
    k = NodeKey.load_or_create(tmp_path / "node.key")
    return k, seal(_result(node_id=kw.get("node_id", k.node_id)), k)


def test_seal_open_roundtrip(tmp_path):
    k = NodeKey.load_or_create(tmp_path / "node.key")
    r = _result(node_id=k.node_id)
    assert open_envelope(seal(r, k), {k.node_id: k.public_key}.get) == r


def test_json_roundtrip_and_job():
    r = _result()
    assert result_from_json(result_to_json(r)) == r
    assert "live" in OUTCOMES
    Job(1, 2, "a.example", "example", 0, "https://a.example/")


def test_key_is_persistent_and_private(tmp_path):
    p = tmp_path / "node.key"
    assert NodeKey.load_or_create(p).node_id == NodeKey.load_or_create(p).node_id
    assert p.stat().st_mode & 0o777 == 0o600
    assert len(NodeKey.load_or_create(p).public_key) == 32


def test_existing_key_not_overwritten(tmp_path):
    p = tmp_path / "node.key"
    p.write_bytes(b"\x01" * 32)
    k = NodeKey.load_or_create(p)
    assert p.read_bytes() == b"\x01" * 32
    assert k.node_id == NodeKey.load_or_create(p).node_id


def test_tampered_payload_rejected(tmp_path):
    k, env = _env(tmp_path)
    d = json.loads(env)
    raw = bytearray(base64.b64decode(d["payload"]))
    raw[len(raw) // 2] ^= 1
    d["payload"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(BadEnvelope):
        open_envelope(canonical_json(d), {k.node_id: k.public_key}.get)


def test_unknown_node_rejected(tmp_path):
    _, env = _env(tmp_path)
    with pytest.raises(BadEnvelope):
        open_envelope(env, lambda n: None)


def test_node_id_mismatch_rejected(tmp_path):
    k, env = _env(tmp_path, node_id="x" * 32)
    with pytest.raises(BadEnvelope, match="node_id does not match"):
        open_envelope(env, {k.node_id: k.public_key}.get)


@pytest.mark.parametrize("bad", [b"", b"not json", b"[]", b'{"node_id":"a"}',
                                 b'{"node_id":1,"payload":"!","signature":"!"}'])
def test_malformed_rejected(bad):
    with pytest.raises(BadEnvelope):
        open_envelope(bad, lambda n: b"\0" * 32)


def test_wrong_key_length_and_wrong_key(tmp_path):
    k, env = _env(tmp_path)
    with pytest.raises(BadEnvelope):
        open_envelope(env, lambda n: b"short")
    other = NodeKey.load_or_create(tmp_path / "other.key")
    with pytest.raises(BadEnvelope):
        open_envelope(env, lambda n: other.public_key)


def test_signed_garbage_payload_rejected(tmp_path):
    k = NodeKey.load_or_create(tmp_path / "node.key")
    payload = b'{"job_id":1}'
    env = canonical_json({
        "node_id": k.node_id,
        "payload": base64.b64encode(payload).decode(),
        "signature": base64.b64encode(k.sign(payload)).decode(),
    })
    with pytest.raises(BadEnvelope):
        open_envelope(env, {k.node_id: k.public_key}.get)


def test_canonical_json_is_stable():
    assert canonical_json({"b": 1, "a": "ü"}) == b'{"a":"\\u00fc","b":1}'


@pytest.mark.parametrize("v", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_rejects_non_finite_floats(v):
    # NaN/Infinity are not JSON; a verifier in another language could not parse them.
    with pytest.raises(ValueError):
        canonical_json({"x": v})


def test_new_key_is_synced_before_it_is_published(tmp_path, monkeypatch):
    events = []
    real_fsync, real_link = os.fsync, os.link
    monkeypatch.setattr(protocol.os, "fsync",
                        lambda fd: (events.append("fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(protocol.os, "link",
                        lambda a, b: (events.append("link"), real_link(a, b))[1])
    NodeKey.load_or_create(tmp_path / "node.key")
    # The key bytes reach the disk before the name appears; the directory
    # entry is synced after.
    assert events[:2] == ["fsync", "link"] and events[2:] == ["fsync"]


def test_concurrent_creators_share_one_key(tmp_path):
    # Several creators race; link() lets exactly one publish, the rest read it.
    p = tmp_path / "node.key"
    barrier = threading.Barrier(8)
    ids = []

    def create():
        barrier.wait()
        ids.append(NodeKey.load_or_create(p).node_id)

    threads = [threading.Thread(target=create) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ids) == 8 and len(set(ids)) == 1
    assert ids[0] == NodeKey(p.read_bytes()).node_id
    assert [x.name for x in tmp_path.iterdir()] == ["node.key"]


@pytest.mark.parametrize("code", [errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP,
                                  errno.ENOSYS, errno.EMLINK])
def test_no_hard_links_is_a_clear_error(tmp_path, monkeypatch, code):
    def no_link(a, b):
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(protocol.os, "link", no_link)
    with pytest.raises(RuntimeError, match="must be on a filesystem that supports hard links"):
        NodeKey.load_or_create(tmp_path / "node.key")
    assert list(tmp_path.iterdir()) == []  # no temp file, no key


def test_other_link_errors_are_raised(tmp_path, monkeypatch):
    def full(a, b):
        raise OSError(errno.ENOSPC, "no space")

    monkeypatch.setattr(protocol.os, "link", full)
    with pytest.raises(OSError, match="no space"):
        NodeKey.load_or_create(tmp_path / "node.key")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("size", [0, 31, 33])
def test_key_of_wrong_length_names_the_file(tmp_path, size):
    p = tmp_path / "node.key"
    p.write_bytes(b"\x01" * size)
    with pytest.raises(ValueError, match=f"node.key.*{size} bytes, expected 32"):
        NodeKey.load_or_create(p)


def test_key_readable_by_others_is_reported(tmp_path, caplog):
    p = tmp_path / "node.key"
    p.write_bytes(b"\x01" * 32)
    p.chmod(0o644)
    with caplog.at_level("WARNING", logger="hakapik.protocol"):
        NodeKey.load_or_create(p)
    assert any("node.key" in r.getMessage() and "0o644" in r.getMessage()
               for r in caplog.records)


def _signed(tmp_path, payload: bytes):
    k = NodeKey.load_or_create(tmp_path / "node.key")
    env = canonical_json({
        "node_id": k.node_id,
        "payload": base64.b64encode(payload).decode(),
        "signature": base64.b64encode(k.sign(payload)).decode(),
    })
    return env, {k.node_id: k.public_key}.get, k


def _mutated(nid, **over):
    d = json.loads(result_to_json(_result(node_id=nid)))
    d.update(over)
    return json.dumps(d).encode()


@pytest.mark.parametrize("over", [
    {"dns": [1]}, {"pages": ["x"]}, {"blobs": [None]}, {"dns": "abc"},
    {"pages": {"a": 1}}, {"outcome": "bogus"}, {"job_id": "7"}, {"job_id": True},
    {"step": 1.5}, {"node_id": 5}, {"error": 3}, {"egress_address": []},
    {"dns": [{"qname": "a"}]},
])
def test_signed_wrong_shapes_rejected(tmp_path, over):
    k = NodeKey.load_or_create(tmp_path / "node.key")
    env, pk, _ = _signed(tmp_path, _mutated(k.node_id, **over))
    with pytest.raises(BadEnvelope):
        open_envelope(env, pk)


def test_signed_nested_field_types_rejected(tmp_path):
    k = NodeKey.load_or_create(tmp_path / "node.key")
    base = json.loads(result_to_json(_result(node_id=k.node_id)))
    cases = [
        ("pages", 0, "outcome", "bogus"), ("pages", 0, "http_status", "200"),
        ("pages", 0, "redirects", "abc"), ("pages", 0, "redirects", [1]),
        ("dns", 0, "ttl", True), ("dns", 0, "answers", [1]),
        ("blobs", 0, "size", "12"), ("blobs", 0, "sha256", None),
    ]
    for sec, i, f, v in cases:
        d = json.loads(json.dumps(base))
        d[sec][i][f] = v
        env, pk, _ = _signed(tmp_path, json.dumps(d).encode())
        with pytest.raises(BadEnvelope):
            open_envelope(env, pk)


def test_deeply_nested_payload_rejected(tmp_path):
    env, pk, _ = _signed(tmp_path, b"[" * 100000 + b"]" * 100000)
    with pytest.raises(BadEnvelope):
        open_envelope(env, pk)
