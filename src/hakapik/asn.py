"""ASN enrichment from an operator-supplied GeoLite2-ASN ``.mmdb`` snapshot.

The file is read once; its bytes go into the blob store and the reader is
opened from those same bytes, so the recorded sha256 is the snapshot that
produced every ASN even if the operator replaces the file meanwhile.
"""

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path

import maxminddb

from hakapik.blobstore import BlobStore

log = logging.getLogger(__name__)

MMDB_MEDIA_TYPE = "application/vnd.maxmind.mmdb"


@dataclass(frozen=True)
class AsnHit:
    asn: int
    org: str | None


class AsnDb:
    def __init__(self, reader, sha256: str, size: int, build_epoch: int) -> None:
        self._reader = reader
        self.size = size
        self.sha256 = sha256
        self.build_epoch = build_epoch

    @classmethod
    def load(cls, path: Path, bs: BlobStore) -> "AsnDb":
        return cls.from_bytes(Path(path).read_bytes(), bs, path)

    @classmethod
    def from_bytes(cls, data: bytes, bs: BlobStore, path: Path) -> "AsnDb":
        """Store the snapshot ``data`` (read from ``path``) and open it."""
        sha = bs.put(data, MMDB_MEDIA_TYPE)
        reader = maxminddb.open_database(bs.path(sha), mode=maxminddb.MODE_MEMORY)
        epoch = reader.metadata().build_epoch
        log.info("ASN database %s loaded: sha256 %s, build epoch %d", path, sha, epoch)
        return cls(reader, sha, len(data), epoch)

    def lookup(self, ip: str) -> AsnHit | None:
        """None for malformed or unknown addresses; a broken database raises."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        rec = self._reader.get(addr)
        if not rec or not isinstance(rec.get("autonomous_system_number"), int):
            return None
        org = rec.get("autonomous_system_organization")
        return AsnHit(rec["autonomous_system_number"], org if isinstance(org, str) else None)
