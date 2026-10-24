"""Signed worker result protocol: the contract between workers and the head.

A worker seals an ``AttemptResult`` into an Ed25519-signed envelope; the head
opens it against the public key it holds for that node id. No I/O besides the
node key file.
"""

import base64
import binascii
import dataclasses
import errno
import hashlib
import json
import logging
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

log = logging.getLogger(__name__)

OUTCOMES = ("dns_fail", "connect_fail", "tls_error", "timeout", "http_error",
            "download", "live", "error")


@dataclass(frozen=True)
class Job:
    job_id: int
    candidate_id: int
    fqdn: str
    registrable: str
    step: int
    url: str  # "https://{fqdn}/"


@dataclass(frozen=True)
class DnsAnswer:
    qname: str
    rrtype: str
    rcode: str  # NOERROR | NXDOMAIN | SERVFAIL | REFUSED | TIMEOUT | ...
    ttl: int | None
    answers: tuple[str, ...]
    resolver: str
    queried_at: str  # RFC 3339 UTC


@dataclass(frozen=True)
class PageResult:
    profile: str  # mobile | desktop | desktop-click1..3
    outcome: str
    http_status: int | None
    final_url: str | None
    server_ip: str | None
    redirects: tuple[str, ...]
    error: str | None
    started_at: str
    finished_at: str


@dataclass(frozen=True)
class BlobRef:
    profile: str
    kind: str  # warc | screenshot | dom | certchain
    sha256: str
    size: int
    media_type: str


@dataclass(frozen=True)
class AttemptResult:
    job_id: int
    step: int
    node_id: str
    egress_address: str | None
    started_at: str
    finished_at: str
    outcome: str
    error: str | None
    dns: tuple[DnsAnswer, ...]
    pages: tuple[PageResult, ...]
    blobs: tuple[BlobRef, ...]


class BadEnvelope(Exception):
    pass


def canonical_json(obj) -> bytes:
    # allow_nan=False: NaN and Infinity are not JSON, so a verifier in another
    # language could not parse (or re-hash) a document holding them.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def result_to_json(r: AttemptResult) -> bytes:
    return canonical_json(dataclasses.asdict(r))


# Field kinds: s=str, i=int, T=list of str, O=outcome; trailing "?" allows null.
_SPECS = {
    DnsAnswer: dict(qname="s", rrtype="s", rcode="s", ttl="i?", answers="T",
                    resolver="s", queried_at="s"),
    PageResult: dict(profile="s", outcome="O", http_status="i?", final_url="s?",
                     server_ip="s?", redirects="T", error="s?", started_at="s",
                     finished_at="s"),
    BlobRef: dict(profile="s", kind="s", sha256="s", size="i", media_type="s"),
}
_TOP = dict(job_id="i", step="i", node_id="s", egress_address="s?", started_at="s",
            finished_at="s", outcome="O", error="s?")


def _check(name: str, kind: str, v):
    if v is None and kind.endswith("?"):
        return None
    k = kind.rstrip("?")
    if k == "s" and isinstance(v, str):
        return v
    if k == "i" and isinstance(v, int) and not isinstance(v, bool):
        return v
    if k == "O" and v in OUTCOMES:
        return v
    if k == "T" and isinstance(v, list) and all(isinstance(x, str) for x in v):
        return tuple(v)
    raise ValueError(f"bad value for {name}: {v!r}")


def _build(cls, d, spec):
    if not isinstance(d, dict) or set(d) != set(spec):
        raise ValueError(f"bad fields for {cls.__name__}")
    return {k: _check(k, spec[k], d[k]) for k in spec}


def result_from_json(b: bytes) -> AttemptResult:
    try:
        d = json.loads(b)
    except RecursionError as e:
        raise ValueError("payload nested too deeply") from e
    if not isinstance(d, dict) or set(d) != set(_TOP) | {"dns", "pages", "blobs"}:
        raise ValueError("bad fields for AttemptResult")
    kw = _build(AttemptResult, {k: d[k] for k in _TOP}, _TOP)
    for name, cls in (("dns", DnsAnswer), ("pages", PageResult), ("blobs", BlobRef)):
        if not isinstance(d[name], list):
            raise ValueError(f"{name} must be a list")
        kw[name] = tuple(cls(**_build(cls, x, _SPECS[cls])) for x in d[name])
    return AttemptResult(**kw)


def _node_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:32]


class NodeKey:
    def __init__(self, seed: bytes) -> None:
        self._sk = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key: bytes = self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.node_id: str = _node_id(self.public_key)

    @classmethod
    def load_or_create(cls, path: Path) -> "NodeKey":
        path = Path(path)
        if not path.exists():
            _create_key(path, os.urandom(32))
        seed = path.read_bytes()
        if len(seed) != 32:
            raise ValueError(
                f"node key {path} is {len(seed)} bytes, expected 32; it is damaged "
                "(deleting it creates a new key, i.e. a new node id)")
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            log.warning("node key %s has mode %s; it should be 0o600", path, oct(mode))
        return cls(seed)

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)


# link() errors meaning "no hard links on this filesystem": not permitted,
# not supported, not implemented, or too many links. (EXDEV cannot occur: the
# temporary file is in the key's own directory.)
_NO_LINK_ERRNOS = (errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS,
                   errno.EMLINK)


def _create_key(path: Path, seed: bytes) -> None:
    """Write a new key file 0o600; never overwrite one another process wrote first.

    The key is written and fsynced under a temporary name, published whole by
    link(), then the directory is fsynced: no reader or crash ever sees a
    short key under the final name. The data directory must support hard
    links (README, Requirements).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp creates the file 0o600; link() publishes it atomically and
    # fails rather than overwrite if another process won the race.
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-key-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(seed)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            return  # another process published its key first; that one is used
        except OSError as e:
            if e.errno in _NO_LINK_ERRNOS:
                raise RuntimeError(
                    f"data_dir {path.parent} must be on a filesystem that supports "
                    "hard links (needed to publish the node key atomically)") from e
            raise
    finally:
        os.unlink(tmp)
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def seal(r: AttemptResult, key: NodeKey) -> bytes:
    payload = result_to_json(r)
    return canonical_json({
        "node_id": key.node_id,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(key.sign(payload)).decode("ascii"),
    })


def open_envelope(env: bytes,
                  public_key_for: Callable[[str], bytes | None]) -> AttemptResult:
    try:
        d = json.loads(env)
        node_id, payload_b64, sig_b64 = d["node_id"], d["payload"], d["signature"]
        if not all(isinstance(x, str) for x in (node_id, payload_b64, sig_b64)):
            raise BadEnvelope("envelope fields must be strings")
        payload = base64.b64decode(payload_b64, validate=True)
        sig = base64.b64decode(sig_b64, validate=True)
    except BadEnvelope:
        raise
    except (ValueError, KeyError, TypeError, RecursionError, binascii.Error) as e:
        raise BadEnvelope(f"malformed envelope: {e}") from e
    pub = public_key_for(node_id)
    if pub is None:
        raise BadEnvelope(f"unknown node {node_id}")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload)
    except (InvalidSignature, ValueError, TypeError) as e:
        raise BadEnvelope(f"bad signature or key: {e!r}") from e
    try:
        r = result_from_json(payload)
    except (ValueError, KeyError, TypeError, RecursionError) as e:
        raise BadEnvelope(f"malformed payload: {e}") from e
    if r.node_id != node_id:
        raise BadEnvelope("payload node_id does not match envelope node_id")
    return r
