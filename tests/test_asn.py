import hashlib

import netaddr
from mmdb_writer import MMDBWriter

from hakapik.asn import AsnDb, AsnHit
from hakapik.blobstore import BlobStore


def _mmdb(tmp_path, asn=64500):
    w = MMDBWriter(ip_version=6, database_type="GeoLite2-ASN", ipv4_compatible=True)
    w.insert_network(netaddr.IPSet(["1.2.3.0/24"]), {
        "autonomous_system_number": asn,
        "autonomous_system_organization": "Example AS",
    })
    path = tmp_path / "asn.mmdb"
    w.to_db_file(str(path))
    return path


def test_lookup_hit_and_miss(tmp_path):
    db = AsnDb.load(_mmdb(tmp_path), BlobStore(tmp_path / "blobs"))
    assert db.lookup("1.2.3.4") == AsnHit(64500, "Example AS")
    assert db.lookup("8.8.8.8") is None and db.lookup("not-an-ip") is None
    assert db.lookup("10.0.0.1") is None and db.lookup("") is None
    assert isinstance(db.build_epoch, int)


def test_snapshot_stored_in_blobstore(tmp_path):
    bs = BlobStore(tmp_path / "blobs")
    db = AsnDb.load(_mmdb(tmp_path), bs)
    assert hashlib.sha256(bs.path(db.sha256).read_bytes()).hexdigest() == db.sha256


def test_replacing_file_after_load_does_not_change_snapshot(tmp_path):
    path = _mmdb(tmp_path)
    db = AsnDb.load(path, BlobStore(tmp_path / "blobs"))
    _mmdb(tmp_path, asn=64501)
    assert db.lookup("1.2.3.4").asn == 64500


def test_reader_errors_surface(tmp_path):
    import pytest

    db = AsnDb.load(_mmdb(tmp_path), BlobStore(tmp_path / "blobs"))

    class Broken:
        def get(self, ip):
            raise RuntimeError("corrupt database")

    db._reader = Broken()
    with pytest.raises(RuntimeError):
        db.lookup("1.2.3.4")
