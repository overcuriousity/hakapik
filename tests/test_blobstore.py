import hashlib

import pytest

from hakapik.blobstore import BlobStore


def test_blobstore_put_is_idempotent_and_readonly(tmp_path):
    bs = BlobStore(tmp_path)
    h = bs.put(b"abc", "application/octet-stream")
    assert h == hashlib.sha256(b"abc").hexdigest()
    assert bs.put(b"abc", "x") == h
    assert (bs.path(h).stat().st_mode & 0o777) == 0o444
    assert bs.path(h) == tmp_path / h[:2] / h[2:4] / h


def test_blobstore_open_reads_back_and_leaves_no_temp_files(tmp_path):
    bs = BlobStore(tmp_path)
    h = bs.put(b"payload", "text/plain")
    with bs.open(h) as f:
        assert f.read() == b"payload"
    assert [p.name for p in bs.path(h).parent.iterdir()] == [h]


@pytest.mark.parametrize(
    "bad", ["", "ab", "../" + "a" * 61, "A" * 64, "g" * 64, "a" * 63, "a" * 65, "a" * 63 + "\n"]
)
def test_blobstore_path_rejects_non_digest(tmp_path, bad):
    with pytest.raises(ValueError):
        BlobStore(tmp_path).path(bad)
