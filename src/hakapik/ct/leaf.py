"""Parse RFC 6962 MerkleTreeLeaf and static-CT TileLeaf structures."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from asn1crypto import x509


@dataclass(frozen=True)
class ParsedLeaf:
    timestamp_ms: int
    entry_type: Literal["x509", "precert"]
    issuer_dn_der: bytes
    serial: bytes
    san_dns: tuple[str, ...]
    not_before: datetime
    not_after: datetime
    raw_len: int


@dataclass(frozen=True)
class LeafError:
    timestamp_ms: int | None
    reason: str


class _Malformed(Exception):
    """A structural problem; ``ts`` is the entry timestamp if already read."""

    def __init__(self, reason: str, ts: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.ts = ts


class _Reader:
    def __init__(self, buf, pos: int = 0):
        self.buf = buf
        self.pos = pos

    def take(self, n: int) -> bytes:
        end = self.pos + n
        if n < 0 or end > len(self.buf):
            raise _Malformed(f"truncated: need {n} bytes at offset {self.pos}")
        data = bytes(self.buf[self.pos : end])
        self.pos = end
        return data

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")


def _san_dns(tbs: x509.TbsCertificate) -> tuple[str, ...]:
    for ext in tbs["extensions"] or []:
        if ext["extn_id"].native == "subject_alt_name":
            return tuple(
                name.native for name in ext["extn_value"].parsed if name.name == "dns_name"
            )
    return ()


def _build(timestamp_ms: int, kind, tbs: x509.TbsCertificate, raw_len: int) -> ParsedLeaf:
    validity = tbs["validity"]
    not_before = validity["not_before"].native
    not_after = validity["not_after"].native
    for when in (not_before, not_after):
        # asn1crypto yields an extended_datetime (not a datetime) for year 0.
        if not isinstance(when, datetime):
            raise ValueError(f"validity {when!r} is out of the datetime range")
    return ParsedLeaf(
        timestamp_ms=timestamp_ms,
        entry_type=kind,
        issuer_dn_der=tbs["issuer"].dump(),
        serial=tbs["serial_number"].contents,
        san_dns=_san_dns(tbs),
        not_before=not_before,
        not_after=not_after,
        raw_len=raw_len,
    )


def _read_entry(r: _Reader) -> tuple[int, Literal["x509", "precert"], bytes]:
    """Read timestamp, entry_type and certificate payload; return the DER."""
    ts = r.uint(8)
    try:
        etype = r.uint(2)
        if etype == 0:
            return ts, "x509", r.take(r.uint(3))
        if etype == 1:
            r.take(32)
            return ts, "precert", r.take(r.uint(3))
        raise _Malformed(f"unknown entry_type {etype}")
    except _Malformed as exc:
        exc.ts = ts
        raise


def _decode(ts: int, kind, der: bytes, raw_len: int) -> ParsedLeaf | LeafError:
    try:
        if kind == "x509":
            tbs = x509.Certificate.load(der)["tbs_certificate"]
        else:
            tbs = x509.TbsCertificate.load(der)
        return _build(ts, kind, tbs, raw_len)
    except Exception as exc:  # asn1crypto raises many types
        return LeafError(ts, f"certificate parse failed: {exc}")


def parse_rfc6962_leaf(leaf_input: bytes) -> ParsedLeaf | LeafError:
    r = _Reader(leaf_input)
    ts: int | None = None
    try:
        version, leaf_type = r.uint(1), r.uint(1)
        if version != 0:
            raise _Malformed(f"unknown version {version}")
        if leaf_type != 0:
            raise _Malformed(f"unknown leaf_type {leaf_type}")
        ts, kind, der = _read_entry(r)
        r.take(r.uint(2))  # extensions
        if r.pos != len(leaf_input):
            raise _Malformed(f"{len(leaf_input) - r.pos} trailing bytes")
    except _Malformed as exc:
        return LeafError(exc.ts if exc.ts is not None else ts, exc.reason)
    return _decode(ts, kind, der, len(leaf_input))


def parse_tile_leaf(
    buf: memoryview, offset: int
) -> tuple[ParsedLeaf | LeafError, int]:
    """Parse one TileLeaf at offset; return it and the offset just past it.

    If the structure cannot be delimited, the returned offset is -1. A
    structurally valid leaf whose certificate fails to decode yields a
    LeafError together with its true next offset.
    """
    if not 0 <= offset <= len(buf):
        return LeafError(None, f"offset {offset} outside the buffer"), -1
    r = _Reader(buf, offset)
    ts: int | None = None
    try:
        ts, kind, der = _read_entry(r)
        r.take(r.uint(2))  # extensions
        if kind == "precert":
            r.take(r.uint(3))  # pre_certificate
        r.take(r.uint(2))  # fingerprints
    except _Malformed as exc:
        return LeafError(exc.ts if exc.ts is not None else ts, exc.reason), -1
    return _decode(ts, kind, der, r.pos - offset), r.pos
