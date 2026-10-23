"""Embedded first-seen index backed by RocksDB (via rocksdict).

Two column families: ``fqdn`` (fqdn -> packed first sighting) and ``cert``
(cert dedup key -> empty marker).

Assumption: a single writer per process (and per database path). The
read-then-write operations are not atomic and no locking is done.
"""

import struct
from pathlib import Path

from rocksdict import BlockBasedOptions, ColumnFamily, Options, Rdict

_FQDN = "fqdn"
_CERT = "cert"
_HEAD = struct.Struct(">QQ")


def _cf_options() -> Options:
    opts = Options(raw_mode=True)
    table = BlockBasedOptions()
    table.set_bloom_filter(10, False)
    opts.set_block_based_table_factory(table)
    return opts


class FirstSeenIndex:
    def __init__(self, path: Path):
        opts = _cf_options()
        opts.create_if_missing(True)
        opts.create_missing_column_families(True)
        self._db = Rdict(
            str(path),
            options=opts,
            column_families={_FQDN: _cf_options(), _CERT: _cf_options()},
        )
        self._fqdn: ColumnFamily = self._db.get_column_family(_FQDN)
        self._cert: ColumnFamily = self._db.get_column_family(_CERT)

    def seen_cert(self, key: bytes) -> bool:
        """Return whether ``key`` was seen before, and mark it seen."""
        if key in self._cert:
            return True
        self._cert[key] = b""
        return False

    def first_seen(self, fqdn: str, ts_ms: int, log_id: str, index: int) -> bool:
        """Record the first sighting of ``fqdn``; True only if newly inserted."""
        key = fqdn.encode("ascii")
        if key in self._fqdn:
            return False
        self._fqdn[key] = _HEAD.pack(ts_ms, index) + log_id.encode()
        return True

    def get(self, fqdn: str) -> tuple[int, str, int] | None:
        value = self._fqdn.get(fqdn.encode("ascii"))
        if value is None:
            return None
        ts_ms, index = _HEAD.unpack_from(value)
        return ts_ms, value[_HEAD.size :].decode(), index

    def close(self) -> None:
        self._fqdn.close()
        self._cert.close()
        self._db.close()

    def __enter__(self) -> "FirstSeenIndex":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
