from datetime import datetime, timezone
from pathlib import Path

import pytest

from hakapik.ct.leaf import LeafError, ParsedLeaf, parse_rfc6962_leaf, parse_tile_leaf

# Expected values: obtained once from the parser, cross-checked with openssl
# on the embedded DER (SANs, serials, validity for the full certificates).
# leaf_x509: xenon2026h2 index 2988588211; leaf_precert: xenon2026h2 index 2988587561.
# tileleaf_*: Let's Encrypt willow 2026h2 data tile x003/x872/021, leaves 2 and 0.
EXPECTED_SANS_X509 = ("5432fa62e219259ae1093a2a226565b6ee8a.eu2.myvolumio.org",)
EXPECTED_TS_X509 = 1792788656650
EXPECTED_ISSUER_X509 = (
    b"0F1\x0b0\t\x06\x03U\x04\x06\x13\x02AT1\x150\x13\x06\x03U\x04\n\x13\x0cZeroSSL GmbH"
    b"1 0\x1e\x06\x03U\x04\x03\x13\x17ZeroSSL ECC DV SSL CA 2"
)
EXPECTED_SERIAL_X509 = bytes.fromhex("00ab8b2e36658d14504471cfcc6b16c4cd")
EXPECTED_NB_X509 = datetime(2026, 8, 23, 0, 0, 0, tzinfo=timezone.utc)
EXPECTED_NA_X509 = datetime(2026, 11, 21, 23, 59, 59, tzinfo=timezone.utc)

EXPECTED_SANS_PRECERT = (
    "9950eab53001792788541807.osu.prod.canaries.quickbeam.acm.aws.dev",
    "san0.9950eab53001792788541807.osu.prod.canaries.quickbeam.acm.aws.dev",
)
EXPECTED_TS_PRECERT = 1792788622394
EXPECTED_SERIAL_PRECERT = bytes.fromhex("0b6fed5b8690261d5ded8c9a8f7080db")

EXPECTED_SANS_TILE_X509 = (
    "*.snlvlgb-tq01385.europe-west4.gcp.privatelink.snowflake.app",
    "*.snlvlgb-tq01385.europe-west4.gcp.snowflake.app",
)
EXPECTED_TS_TILE_X509 = 1792788683631
EXPECTED_SERIAL_TILE_X509 = bytes.fromhex("05d950a109c1792da42dec23ab843b3a89ba")

EXPECTED_SANS_TILE_PRECERT = ("ad12aa884.dcerg5.azurecertificateservice.azure-int.net",)
EXPECTED_SERIAL_TILE_PRECERT = bytes.fromhex("0dbd1c4f363247322df7501256ea4bdc")


FIX = Path(__file__).parent / "fixtures"


def load(name: str) -> bytes:
    return (FIX / name).read_bytes()


@pytest.fixture
def leaf_x509():
    return load("leaf_x509.bin")


@pytest.fixture
def leaf_precert():
    return load("leaf_precert.bin")


@pytest.fixture
def tile_bytes():
    return load("tile_data_small.bin")


def test_parse_x509_leaf_sans(leaf_x509):
    p = parse_rfc6962_leaf(leaf_x509)
    assert isinstance(p, ParsedLeaf)
    assert p.entry_type == "x509" and p.san_dns == EXPECTED_SANS_X509
    assert p.timestamp_ms == EXPECTED_TS_X509
    assert p.serial == EXPECTED_SERIAL_X509
    assert p.not_before == EXPECTED_NB_X509 and p.not_after == EXPECTED_NA_X509
    assert p.not_before.tzinfo is not None
    assert p.raw_len == len(leaf_x509)
    # The whole issuer Name (C=AT, O=ZeroSSL GmbH, CN=ZeroSSL ECC DV SSL CA 2).
    assert p.issuer_dn_der == EXPECTED_ISSUER_X509


def test_parse_precert_leaf_uses_tbs(leaf_precert):
    p = parse_rfc6962_leaf(leaf_precert)
    assert isinstance(p, ParsedLeaf)
    assert p.entry_type == "precert" and p.serial == EXPECTED_SERIAL_PRECERT
    assert p.san_dns == EXPECTED_SANS_PRECERT
    assert p.timestamp_ms == EXPECTED_TS_PRECERT


def test_parse_tile_leaf_x509():
    buf = load("tileleaf_x509.bin")
    p, off = parse_tile_leaf(memoryview(buf), 0)
    assert isinstance(p, ParsedLeaf) and p.entry_type == "x509"
    assert off == len(buf)
    assert p.san_dns == EXPECTED_SANS_TILE_X509
    assert p.serial == EXPECTED_SERIAL_TILE_X509
    assert p.timestamp_ms == EXPECTED_TS_TILE_X509


def test_parse_tile_leaf_precert():
    buf = load("tileleaf_precert.bin")
    p, off = parse_tile_leaf(memoryview(buf), 0)
    assert isinstance(p, ParsedLeaf) and p.entry_type == "precert"
    assert off == len(buf)
    assert p.san_dns == EXPECTED_SANS_TILE_PRECERT
    assert p.serial == EXPECTED_SERIAL_TILE_PRECERT


def test_parse_tile_leaf_advances_offset(tile_bytes):
    mv = memoryview(tile_bytes)
    offsets = [0]
    for _ in range(8):
        p, off = parse_tile_leaf(mv, offsets[-1])
        assert isinstance(p, ParsedLeaf)
        assert off > offsets[-1]
        offsets.append(off)
    assert offsets[-1] == len(tile_bytes)


def test_parse_leaf_garbage_returns_error_record():
    r = parse_rfc6962_leaf(b"\x00" * 40)
    assert isinstance(r, LeafError)


def test_truncated_leaf_returns_error_with_timestamp(leaf_x509):
    r = parse_rfc6962_leaf(leaf_x509[:100])
    assert isinstance(r, LeafError) and r.timestamp_ms == EXPECTED_TS_X509


def test_truncated_before_timestamp_has_none():
    r = parse_rfc6962_leaf(b"\x00\x00\x00")
    assert isinstance(r, LeafError) and r.timestamp_ms is None


def test_unknown_entry_type_is_error(leaf_x509):
    bad = leaf_x509[:10] + b"\x00\x07" + leaf_x509[12:]
    r = parse_rfc6962_leaf(bad)
    assert isinstance(r, LeafError) and "entry_type" in r.reason


def test_tile_truncated_returns_error_not_raise():
    buf = load("tileleaf_x509.bin")[:200]
    r, off = parse_tile_leaf(memoryview(buf), 0)
    assert isinstance(r, LeafError)
    assert off == -1


def test_tile_corrupt_cert_keeps_true_offset():
    buf = bytearray(load("tileleaf_x509.bin"))
    buf[40:56] = b"\xff" * 16
    r, off = parse_tile_leaf(memoryview(bytes(buf)), 0)
    assert isinstance(r, LeafError)
    assert off == len(buf)


def test_ip_only_san_gives_empty_tuple():
    p = parse_rfc6962_leaf(load("leaf_x509_ip_only.bin"))
    assert isinstance(p, ParsedLeaf) and p.san_dns == ()


def _cert_of(leaf: bytes) -> bytes:
    n = int.from_bytes(leaf[12:15], "big")
    return leaf[15 : 15 + n]


def _x509_leaf(ts: int, der: bytes, extensions: bytes = b"\x00\x00") -> bytes:
    return (
        b"\x00\x00" + ts.to_bytes(8, "big") + b"\x00\x00"
        + len(der).to_bytes(3, "big") + der + extensions
    )


def test_truncated_extensions_keep_timestamp(leaf_x509):
    der = _cert_of(leaf_x509)
    r = parse_rfc6962_leaf(_x509_leaf(EXPECTED_TS_X509, der, b"\x00\x09ab"))
    assert isinstance(r, LeafError) and r.timestamp_ms == EXPECTED_TS_X509
    assert "truncated" in r.reason


def test_timestamp_zero_is_kept_not_dropped(leaf_x509):
    der = _cert_of(leaf_x509)
    r = parse_rfc6962_leaf(_x509_leaf(0, der, b"\x00\x09ab"))
    assert isinstance(r, LeafError) and r.timestamp_ms == 0
    tile = b"\x00" * 8 + b"\x00\x00" + len(der).to_bytes(3, "big") + der + b"\x00"
    r, off = parse_tile_leaf(memoryview(tile), 0)
    assert isinstance(r, LeafError) and r.timestamp_ms == 0 and off == -1


@pytest.mark.parametrize(
    ("patch", "word"),
    [(lambda b: b"\x01" + b[1:], "version"), (lambda b: b[:1] + b"\x01" + b[2:], "leaf_type")],
)
def test_unknown_version_or_leaf_type_is_error(leaf_x509, patch, word):
    r = parse_rfc6962_leaf(patch(leaf_x509))
    assert isinstance(r, LeafError) and word in r.reason


def test_trailing_bytes_are_error(leaf_x509):
    r = parse_rfc6962_leaf(leaf_x509 + b"\x00")
    assert isinstance(r, LeafError) and "trailing" in r.reason
    assert r.timestamp_ms == EXPECTED_TS_X509


@pytest.mark.parametrize("offset", [-1, -100, 10**6])
def test_tile_offset_outside_buffer_is_error(offset):
    buf = load("tileleaf_x509.bin")
    r, off = parse_tile_leaf(memoryview(buf), offset)
    assert isinstance(r, LeafError) and off == -1


def test_year_zero_validity_is_error_not_extended_datetime(leaf_x509):
    from asn1crypto import core, util, x509

    cert = x509.Certificate.load(_cert_of(leaf_x509))
    cert["tbs_certificate"]["validity"]["not_before"] = x509.Time(
        {"general_time": core.GeneralizedTime(util.extended_datetime(0, 1, 1, tzinfo=timezone.utc))}
    )
    r = parse_rfc6962_leaf(_x509_leaf(EXPECTED_TS_X509, cert.dump(force=True)))
    assert isinstance(r, LeafError) and "out of the datetime range" in r.reason
    assert r.timestamp_ms == EXPECTED_TS_X509
