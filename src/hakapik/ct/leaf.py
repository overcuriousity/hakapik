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


class _Truncated(Exception):
    pass


class _Reader:
    def __init__(self, buf, pos: int = 0):
        self.buf = buf
        self.pos = pos

    def take(self, n: int) -> bytes:
        end = self.pos + n
        if n < 0 or end > len(self.buf):
            raise _Truncated(f"truncated: need {n} bytes at offset {self.pos}")
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
    return ParsedLeaf(
        timestamp_ms=timestamp_ms,
        entry_type=kind,
        issuer_dn_der=tbs["issuer"].dump(),
        serial=tbs["serial_number"].contents,
        san_dns=_san_dns(tbs),
        not_before=validity["not_before"].native,
        not_after=validity["not_after"].native,
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
    except _Truncated as exc:
        raise _Truncated(str(exc), ts) from exc
    raise ValueError(ts, f"unknown entry_type {etype}")


def _decode(ts: int, kind, der: bytes, raw_len: int) -> ParsedLeaf | LeafError:
    try:
        if kind == "x509":
            tbs = x509.Certificate.load(der)["tbs_certificate"]
        else:
            tbs = x509.TbsCertificate.load(der)
        return _build(ts, kind, tbs, raw_len)
    except Exception as exc:  # asn1crypto raises many types
        return LeafError(ts, f"certificate parse failed: {exc}")


def _ts_of(exc: Exception) -> int | None:
    return exc.args[1] if len(exc.args) > 1 else None


def parse_rfc6962_leaf(leaf_input: bytes) -> ParsedLeaf | LeafError:
    r = _Reader(leaf_input)
    try:
        r.take(2)  # version, leaf_type
        ts, kind, der = _read_entry(r)
        r.take(r.uint(2))  # extensions
    except _Truncated as exc:
        return LeafError(_ts_of(exc), str(exc.args[0]))
    except ValueError as exc:
        return LeafError(exc.args[0], exc.args[1])
    return _decode(ts, kind, der, len(leaf_input))


def parse_tile_leaf(
    buf: memoryview, offset: int
) -> tuple[ParsedLeaf | LeafError, int]:
    """Parse one TileLeaf at offset; return it and the offset just past it.

    If the structure cannot be delimited, the returned offset is len(buf).
    """
    r = _Reader(buf, offset)
    ts: int | None = None
    try:
        ts, kind, der = _read_entry(r)
        r.take(r.uint(2))  # extensions
        if kind == "precert":
            r.take(r.uint(3))  # pre_certificate
        r.take(r.uint(2))  # fingerprints
    except _Truncated as exc:
        return LeafError(_ts_of(exc) or ts, str(exc.args[0])), len(buf)
    except ValueError as exc:
        return LeafError(exc.args[0], exc.args[1]), len(buf)
    return _decode(ts, kind, der, r.pos - offset), r.pos
