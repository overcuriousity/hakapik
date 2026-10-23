"""Content-addressed blob store on the local filesystem.

Blobs live at ``root/ab/cd/<sha256 hex>`` and are immutable (mode 0o444).
The store is deliberately dumb: ``media_type`` is accepted for call-site
clarity but is not recorded here; callers record it in Postgres.
"""

import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import BinaryIO

_HEX64 = re.compile(r"[0-9a-f]{64}")


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
        if dest.exists():
            return digest
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o444)
            os.replace(tmp, dest)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return digest

    def open(self, hexdigest: str) -> BinaryIO:
        return open(self.path(hexdigest), "rb")
