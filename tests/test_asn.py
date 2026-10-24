import hashlib

import pytest

from hakapik.asn import AsnDb, AsnHit
from hakapik.blobstore import BlobStore


def test_lookup_hit_and_miss(tmp_path, asn_mmdb):
    db = AsnDb.load(asn_mmdb(), BlobStore(tmp_path / "blobs"))
    assert db.lookup("1.2.3.4") == AsnHit(64500, "Example AS")
    assert db.lookup("8.8.8.8") is None and db.lookup("not-an-ip") is None
    assert db.lookup("10.0.0.1") is None and db.lookup("") is None
    assert isinstance(db.build_epoch, int)


def test_snapshot_stored_in_blobstore(tmp_path, asn_mmdb):
    bs = BlobStore(tmp_path / "blobs")
    db = AsnDb.load(asn_mmdb(), bs)
    assert hashlib.sha256(bs.path(db.sha256).read_bytes()).hexdigest() == db.sha256


def test_replacing_file_after_load_does_not_change_snapshot(tmp_path, asn_mmdb):
    db = AsnDb.load(asn_mmdb(), BlobStore(tmp_path / "blobs"))
    asn_mmdb(asn=64501)
    assert db.lookup("1.2.3.4").asn == 64500


def test_reader_errors_surface(tmp_path, asn_mmdb):
    db = AsnDb.load(asn_mmdb(), BlobStore(tmp_path / "blobs"))

    class Broken:
        def get(self, ip):
            raise RuntimeError("corrupt database")

    db._reader = Broken()
    with pytest.raises(RuntimeError):
        db.lookup("1.2.3.4")


def test_close_closes_the_reader_and_later_lookups_fail(tmp_path, asn_mmdb):
    # A closed MODE_MEMORY reader of maxminddb still answers, so AsnDb drops it:
    # a lookup after close is an error, not a silent answer.
    db = AsnDb.load(asn_mmdb(), BlobStore(tmp_path / "blobs"))
    closed = []
    real_close = db._reader.close
    db._reader.close = lambda: (closed.append(True), real_close())[1]
    db.close()
    db.close()  # idempotent
    assert closed == [True]
    with pytest.raises(RuntimeError, match="closed"):
        db.lookup("1.2.3.4")
