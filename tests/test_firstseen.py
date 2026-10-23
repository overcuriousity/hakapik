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
