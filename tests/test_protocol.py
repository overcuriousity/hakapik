import base64
import json

import pytest

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
    with pytest.raises(BadEnvelope):
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
        "signature": base64.b64encode(k._sk.sign(payload)).decode(),
    })
    with pytest.raises(BadEnvelope):
        open_envelope(env, {k.node_id: k.public_key}.get)


def test_canonical_json_is_stable():
    assert canonical_json({"b": 1, "a": "ü"}) == b'{"a":"\\u00fc","b":1}'
