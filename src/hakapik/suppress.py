"""Suppression lists: names that are never fetch candidates."""

from __future__ import annotations

import csv
from collections.abc import Iterable
from pathlib import Path

from hakapik.names import _EXTRACT, NameRecord


def _private_suffixes() -> frozenset[str]:
    """PSL private-domain suffixes (e.g. pages.dev) from the bundled snapshot."""
    return frozenset(
        s.lower() for s in _EXTRACT._get_tld_extractor().private_tlds if "." in s
    )


class Suppressor:
    def __init__(self, tranco_apexes: frozenset[str], public_apexes: frozenset[str]):
        self._tranco = tranco_apexes
        self._public = public_apexes

    @classmethod
    def from_files(
        cls, tranco_csv: Path, top_n: int, public_apexes: Iterable[str]
    ) -> Suppressor:
        tranco: set[str] = set()
        taken = 0
        with open(tranco_csv, newline="") as fh:
            for row in csv.reader(fh):
                # Data rows are "rank,domain". Blank lines and a header row
                # (non-numeric rank) are skipped and do not count toward top_n.
                if len(row) < 2 or not row[0].strip().isdigit():
                    continue
                if taken >= top_n:
                    break
                taken += 1
                domain = row[1].strip().lower()
                domain = domain.removeprefix("www.")
                if domain:
                    tranco.add(domain)
        # Operator input: tolerate case, spaces, a trailing dot and a "*." prefix.
        configured = {
            a for p in public_apexes if (a := p.strip().lower().removeprefix("*.").strip("."))
        }
        public = _private_suffixes() | configured
        return cls(frozenset(tranco), frozenset(public))

    def top_listed(self, registrable: str) -> bool:
        """True if the registrable domain is in the Tranco top set."""
        return registrable in self._tranco

    def reason(self, rec: NameRecord) -> str | None:
        fqdn = rec.fqdn
        # normalize() marks a bare public suffix (e.g. pages.dev) invalid because
        # it has no registrable part, so this check must precede the validity one.
        if rec.wildcard:
            return "wildcard"
        if fqdn in self._public:
            return "public_apex"
        if not rec.valid:
            return "invalid"
        if fqdn in self._tranco or (
            fqdn.startswith("www.") and fqdn[4:] in self._tranco
        ):
            return "tranco"
        return None
