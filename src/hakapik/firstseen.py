"""Embedded first-seen index backed by RocksDB (via rocksdict).

Two column families: ``fqdn`` (fqdn -> packed first sighting) and ``cert``
(cert dedup key -> empty marker).

Assumption: a single writer per process (and per database path). The
read-then-write operations are not atomic and no locking is done.
"""

import struct
from pathlib import Path
from types import TracebackType
from typing import Self

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


def _fqdn_key(fqdn: str) -> bytes:
    try:
        return fqdn.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(f"fqdn is not ASCII/IDNA-normalised: {fqdn!r}") from None


class FirstSeenIndex:
    """First-seen index; see the module docstring for the writer assumption.

    Canonical-name contract: callers pass ``NameRecord.key`` of a record from
    ``hakapik.names.normalize`` with ``valid=True``, i.e. a lowercase IDNA
    A-label name without trailing dot, prefixed ``*.`` for a wildcard. The
    index does not normalise: a differently spelled name is a different key.
    Non-ASCII names raise ``ValueError``, as do a timestamp or index outside
    the unsigned 64-bit range, and any use after ``close()``.
    """

    def __init__(self, path: Path):
        opts = _cf_options()
        opts.create_if_missing(True)
        opts.create_missing_column_families(True)
        self._closed = False
        self._db = Rdict(
            str(path),
            options=opts,
            column_families={_FQDN: _cf_options(), _CERT: _cf_options()},
        )
        self._fqdn: ColumnFamily = self._db.get_column_family(_FQDN)
        self._cert: ColumnFamily = self._db.get_column_family(_CERT)

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("FirstSeenIndex is closed")

    def has_cert(self, key: bytes) -> bool:
        """Return whether ``key`` was marked seen, without marking it."""
        self._check_open()
        return key in self._cert

    def seen_cert(self, key: bytes) -> bool:
        """Return whether ``key`` was seen before, and mark it seen."""
        self._check_open()
        if key in self._cert:
            return True
        self._cert[key] = b""
        return False

    def first_seen(self, fqdn: str, ts_ms: int, log_id: str, index: int) -> bool:
        """Record the first sighting of ``fqdn``; True only if newly inserted."""
        self._check_open()
        key = _fqdn_key(fqdn)
        if key in self._fqdn:
            return False
        try:
            head = _HEAD.pack(ts_ms, index)
        except struct.error:
            raise ValueError(
                f"ts_ms and index must fit an unsigned 64-bit integer: {ts_ms!r}, {index!r}"
            ) from None
        self._fqdn[key] = head + log_id.encode("utf-8")
        return True

    def get(self, fqdn: str) -> tuple[int, str, int] | None:
        self._check_open()
        value = self._fqdn.get(_fqdn_key(fqdn))
        if value is None:
            return None
        ts_ms, index = _HEAD.unpack_from(value)
        return ts_ms, value[_HEAD.size :].decode("utf-8"), index

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Every handle is closed even if an earlier close raises.
        try:
            try:
                self._fqdn.close()
            finally:
                self._cert.close()
        finally:
            self._db.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
