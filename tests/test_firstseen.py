import pytest

from hakapik.firstseen import FirstSeenIndex


def test_first_seen_inserts_once(tmp_path):
    with FirstSeenIndex(tmp_path / "idx") as ix:
        assert ix.first_seen("a.example", 1, "L", 7) is True
        assert ix.first_seen("a.example", 2, "M", 9) is False
        assert ix.get("a.example") == (1, "L", 7)
        assert ix.get("missing.example") is None


def test_seen_cert_marks(tmp_path):
    with FirstSeenIndex(tmp_path / "idx") as ix:
        k = b"\x01" * 32
        assert ix.seen_cert(k) is False and ix.seen_cert(k) is True


def test_has_cert_reads_without_marking(tmp_path):
    with FirstSeenIndex(tmp_path / "idx") as ix:
        k = b"\x03" * 32
        assert ix.has_cert(k) is False and ix.has_cert(k) is False
        ix.seen_cert(k)
        assert ix.has_cert(k) is True


def test_persists_across_reopen(tmp_path):
    path = tmp_path / "idx"
    ix = FirstSeenIndex(path)
    ix.first_seen("a.example", 5, "L", 3)
    ix.seen_cert(b"\x02" * 32)
    ix.close()
    with FirstSeenIndex(path) as ix2:
        assert ix2.get("a.example") == (5, "L", 3)
        assert ix2.first_seen("a.example", 9, "M", 1) is False
        assert ix2.seen_cert(b"\x02" * 32) is True


def test_close_is_idempotent(tmp_path):
    ix = FirstSeenIndex(tmp_path / "idx")
    ix.close()
    ix.close()


def test_close_after_with_block(tmp_path):
    with FirstSeenIndex(tmp_path / "idx") as ix:
        ix.first_seen("a.example", 1, "L", 1)
    ix.close()


def test_non_ascii_fqdn_rejected_and_not_written(tmp_path):
    with FirstSeenIndex(tmp_path / "idx") as ix:
        with pytest.raises(ValueError):
            ix.first_seen("prüfung.de", 1, "L", 1)
        with pytest.raises(ValueError):
            ix.get("prüfung.de")
        assert "prüfung.de".encode() not in ix._fqdn  # the rejected key itself
        assert ix.get("pruefung.de") is None
        assert ix.get("xn--prfung-t2a.de") is None


@pytest.mark.parametrize("ts_ms, index", [(-1, 0), (0, -1), (2**64, 0), (0, 2**64)])
def test_out_of_u64_range_rejected_and_not_written(tmp_path, ts_ms, index):
    with FirstSeenIndex(tmp_path / "idx") as ix:
        with pytest.raises(ValueError, match="64-bit"):
            ix.first_seen("a.example", ts_ms, "L", index)
        assert ix.get("a.example") is None


def test_u64_bounds_roundtrip(tmp_path):
    with FirstSeenIndex(tmp_path / "idx") as ix:
        assert ix.first_seen("a.example", 0, "L", 2**64 - 1)
        assert ix.get("a.example") == (0, "L", 2**64 - 1)


def test_use_after_close_raises(tmp_path):
    ix = FirstSeenIndex(tmp_path / "idx")
    ix.close()
    with pytest.raises(ValueError, match="closed"):
        ix.first_seen("a.example", 1, "L", 1)
    with pytest.raises(ValueError, match="closed"):
        ix.get("a.example")
    with pytest.raises(ValueError, match="closed"):
        ix.seen_cert(b"k")
    with pytest.raises(ValueError, match="closed"):
        ix.has_cert(b"k")


def test_close_closes_every_handle_when_a_column_family_close_raises(tmp_path):
    ix = FirstSeenIndex(tmp_path / "idx")
    calls = []
    real_cert, real_db = ix._cert, ix._db

    class Boom:
        def close(self):
            calls.append("fqdn")
            raise RuntimeError("boom")

    class Spy:
        def __init__(self, inner, name):
            self.inner, self.name = inner, name

        def close(self):
            calls.append(self.name)
            self.inner.close()

    ix._fqdn, ix._cert, ix._db = Boom(), Spy(real_cert, "cert"), Spy(real_db, "db")
    with pytest.raises(RuntimeError, match="boom"):
        ix.close()
    assert calls == ["fqdn", "cert", "db"]
