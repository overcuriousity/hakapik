"""Content-addressed blob store on the local filesystem.

Blobs live at ``root/ab/cd/<sha256 hex>`` and are immutable (mode 0o444);
the mtime is refreshed on every put of an existing blob.
The store is deliberately dumb: ``media_type`` is accepted for call-site
clarity but is not recorded here; callers record it in Postgres.
"""

import hashlib
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import BinaryIO

_log = logging.getLogger(__name__)
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _tolerate(digest: str, problem: str, op: str, fn, *args) -> None:
    """Run ``fn(*args)``, named ``op``, on an existing blob.

    A PermissionError (e.g. a file owned by another user) is only logged.
    """
    try:
        fn(*args)
    except PermissionError as e:
        _log.warning(
            "blob %s exists but %s (%s: %r); keeping it", digest, problem, op, e
        )


class BlobStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def path(self, hexdigest: str) -> Path:
        """Path of a blob; ``hexdigest`` must be 64 lowercase hex characters.

        Validated because callers (``prune_raw``) build paths from DB values.
        """
        if not isinstance(hexdigest, str) or not _HEX64.fullmatch(hexdigest):
            raise ValueError(f"not a SHA-256 hex digest: {hexdigest!r}")
        return self.root / hexdigest[:2] / hexdigest[2:4] / hexdigest

    def put(self, data: bytes, media_type: str) -> str:
        """Store ``data`` and return its hex SHA-256. ``media_type`` is ignored."""
        digest = hashlib.sha256(data).hexdigest()
        dest = self.path(digest)
        try:
            # Content-addressed, so the bytes are right; the mode is not
            # guaranteed if someone touched the file.
            if (dest.stat().st_mode & 0o777) != 0o444:
                _tolerate(
                    digest, "its mode cannot be fixed", "chmod", os.chmod, dest, 0o444
                )
            # A file's age is the time since its last put: the orphan sweep
            # (db.sweep_orphan_blobs) leaves young files alone.
            _tolerate(digest, "its mtime cannot be refreshed", "utime", os.utime, dest)
            return digest
        except FileNotFoundError:
            pass  # absent, or pruned meanwhile: write it
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o444)
            os.replace(tmp, dest)
            _fsync_dir(dest.parent)  # make the rename itself durable
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return digest

    def open(self, hexdigest: str) -> BinaryIO:
        return open(self.path(hexdigest), "rb")
