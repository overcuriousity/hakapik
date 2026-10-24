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


def test_blobstore_put_fsyncs_the_directory_after_the_rename(tmp_path, monkeypatch):
    import os
    import stat

    synced_dirs = []
    real = os.fsync

    def spy(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            synced_dirs.append(os.readlink(f"/proc/self/fd/{fd}"))
        real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    bs = BlobStore(tmp_path)
    h = bs.put(b"durable", "x")
    assert synced_dirs == [str(bs.path(h).parent)]


def test_blobstore_put_restores_mode_of_existing_blob(tmp_path):
    bs = BlobStore(tmp_path)
    h = bs.put(b"abc", "x")
    bs.path(h).chmod(0o666)
    assert bs.put(b"abc", "x") == h
    assert (bs.path(h).stat().st_mode & 0o777) == 0o444


def test_blobstore_put_rewrites_a_blob_pruned_between_check_and_stat(tmp_path, monkeypatch):
    from pathlib import Path

    bs = BlobStore(tmp_path)
    h = bs.put(b"abc", "x")
    real = Path.stat
    calls = []

    def stat(self, *a, **kw):
        if self == bs.path(h) and not calls:
            calls.append(1)
            self.chmod(0o644)
            self.unlink()  # pruned after exists() said yes
            raise FileNotFoundError(str(self))
        return real(self, *a, **kw)

    monkeypatch.setattr(Path, "stat", stat)
    assert bs.put(b"abc", "x") == h
    assert calls and bs.path(h).read_bytes() == b"abc"


def test_blobstore_put_tolerates_unfixable_mode_of_existing_blob(tmp_path, monkeypatch, caplog):
    import os

    bs = BlobStore(tmp_path)
    h = bs.put(b"abc", "x")
    bs.path(h).chmod(0o666)

    def deny(path, mode):
        raise PermissionError("not owner")

    monkeypatch.setattr(os, "chmod", deny)
    with caplog.at_level("WARNING", logger="hakapik.blobstore"):
        assert bs.put(b"abc", "x") == h
    assert any(h in r.getMessage() for r in caplog.records)


def test_blobstore_put_of_an_existing_blob_refreshes_its_mtime(tmp_path):
    import os

    bs = BlobStore(tmp_path)
    h = bs.put(b"abc", "x")
    os.utime(bs.path(h), (1000, 1000))
    assert bs.put(b"abc", "x") == h
    assert bs.path(h).stat().st_mtime > 1000
