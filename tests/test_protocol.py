import base64
import errno
import fcntl
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


def _no_link(a, b):
    raise OSError(errno.EPERM, "hard links not supported")


def test_key_created_without_hard_links(tmp_path, monkeypatch):
    monkeypatch.setattr(protocol.os, "link", _no_link)
    p = tmp_path / "node.key"
    k = NodeKey.load_or_create(p)
    assert len(p.read_bytes()) == 32 and p.stat().st_mode & 0o777 == 0o600
    assert NodeKey.load_or_create(p).node_id == k.node_id
    assert [x.name for x in tmp_path.iterdir()] == ["node.key"]


def test_no_link_waits_for_a_concurrent_creator_and_never_overwrites(tmp_path,
                                                                     monkeypatch):
    # Another process holds the lock and publishes its key whole (by rename)
    # a moment later: this one waits, then uses that key.
    monkeypatch.setattr(protocol.os, "link", _no_link)
    p = tmp_path / "node.key"
    (tmp_path / "node.key.lock").touch()
    theirs = NodeKey(b"\x05" * 32)

    def other_process():
        src = tmp_path / "theirs.tmp"
        src.write_bytes(b"\x05" * 32)
        src.chmod(0o600)
        os.rename(src, p)

    timer = threading.Timer(0.2, other_process)
    timer.start()
    try:
        assert NodeKey.load_or_create(p).node_id == theirs.node_id
    finally:
        timer.join()
    assert p.read_bytes() == b"\x05" * 32


def test_no_link_rename_does_not_replace_a_key_that_appeared(tmp_path, monkeypatch):
    # The key appears between the exists() check and taking the lock.
    p = tmp_path / "node.key"

    def link_then_other_wins(a, b):
        p.write_bytes(b"\x06" * 32)
        p.chmod(0o600)
        _no_link(a, b)

    monkeypatch.setattr(protocol.os, "link", link_then_other_wins)
    assert NodeKey.load_or_create(p).node_id == NodeKey(b"\x06" * 32).node_id
    assert sorted(x.name for x in tmp_path.iterdir()) == ["node.key"]


@pytest.mark.parametrize("code", [errno.ENOSYS, errno.EMLINK, errno.ENOTSUP])
def test_every_missing_link_errno_takes_the_fallback(tmp_path, monkeypatch, code):
    def no_link(a, b):
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(protocol.os, "link", no_link)
    p = tmp_path / "node.key"
    NodeKey.load_or_create(p)
    assert len(p.read_bytes()) == 32 and sorted(x.name for x in tmp_path.iterdir()) == [
        "node.key"]


def test_no_link_lock_without_a_holder_is_taken_over(tmp_path, monkeypatch, caplog):
    # A lock file nobody holds an flock on: its creator died (the kernel drops
    # the flock with the process). The waiter removes it and creates the key.
    monkeypatch.setattr(protocol.os, "link", _no_link)
    monkeypatch.setattr(protocol, "KEY_LOCK_WAIT_S", 0.1)
    (tmp_path / "node.key.lock").touch()
    p = tmp_path / "node.key"
    with caplog.at_level("WARNING", logger="hakapik.protocol"):
        NodeKey.load_or_create(p)
    assert len(p.read_bytes()) == 32
    assert sorted(x.name for x in tmp_path.iterdir()) == ["node.key"]
    assert any("node.key.lock" in r.getMessage() for r in caplog.records)


def test_no_link_lock_with_a_live_holder_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(protocol.os, "link", _no_link)
    monkeypatch.setattr(protocol, "KEY_LOCK_WAIT_S", 0.1)
    lock = tmp_path / "node.key.lock"
    holder = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)  # an fd of its own: a live creator
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        with pytest.raises(RuntimeError, match="node.key.lock"):
            NodeKey.load_or_create(tmp_path / "node.key")
        assert lock.exists() and not (tmp_path / "node.key").exists()
    finally:
        os.close(holder)


def test_no_link_creator_removes_the_lock_under_its_flock(tmp_path, monkeypatch):
    lock = tmp_path / "node.key.lock"
    seen = []
    real_rename, real_unlink = os.rename, os.unlink

    def probe(what):
        fd = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            seen.append((what, "free"))
        except BlockingIOError:
            seen.append((what, "held"))
        finally:
            os.close(fd)

    def rename(a, b):
        probe("rename")
        real_rename(a, b)

    def unlink(p):
        if os.fspath(p) == os.fspath(lock):
            probe("unlink")
        real_unlink(p)

    monkeypatch.setattr(protocol.os, "link", _no_link)
    monkeypatch.setattr(protocol.os, "rename", rename)
    monkeypatch.setattr(protocol.os, "unlink", unlink)
    NodeKey.load_or_create(tmp_path / "node.key")
    assert seen == [("rename", "held"), ("unlink", "held")]
    assert sorted(x.name for x in tmp_path.iterdir()) == ["node.key"]


def test_no_link_lock_fd_closed_when_flock_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(protocol.os, "link", _no_link)

    def broken(fd, op):
        raise OSError(errno.ENOLCK, "no locks")

    before = set(os.listdir("/proc/self/fd"))
    monkeypatch.setattr(protocol.fcntl, "flock", broken)
    with pytest.raises(OSError, match="no locks"):
        NodeKey.load_or_create(tmp_path / "node.key")
    monkeypatch.undo()
    assert set(os.listdir("/proc/self/fd")) <= before
    assert list(tmp_path.iterdir()) == []  # no lock file left behind


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
