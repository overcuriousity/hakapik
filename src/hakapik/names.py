"""Name normalisation for the first-seen index and suppression lists."""

from __future__ import annotations

from dataclasses import dataclass

import idna
import tldextract

# Bundled snapshot only: no network fetch, no cache directory writes.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


@dataclass(frozen=True)
class NameRecord:
    """A normalised name.

    For a valid record ``fqdn`` is the canonical IDNA (A-label, lowercase,
    no trailing dot, no ``*.``) form. For an invalid one (``valid=False``) it
    is only the stripped, lowercased input, which may be non-ASCII or
    arbitrary text: use it for logs, never as an index key (``FirstSeenIndex``
    rejects non-ASCII keys).
    """

    fqdn: str
    registrable: str
    wildcard: bool
    idn: bool
    valid: bool

    @property
    def key(self) -> str:
        """First-seen index key: ``*.`` + fqdn for a wildcard, else the fqdn.

        A wildcard and its apex share ``fqdn`` but are distinct sightings, so
        ``*.x.com`` must not mark ``x.com`` as already seen.
        """
        return "*." + self.fqdn if self.wildcard else self.fqdn


def _registrable(fqdn: str) -> str:
    ext = _EXTRACT(fqdn)
    if not ext.suffix:
        return ""
    # tldextract>=5.4 (pinned in pyproject) always has this property; the older
    # registered_domain alias is deprecated and warns.
    return ext.top_domain_under_public_suffix


def normalize(name: str) -> NameRecord:
    raw = name.strip()
    if raw.endswith("."):
        raw = raw[:-1]
    wildcard = raw.startswith("*.")
    if wildcard:
        raw = raw[2:]
    raw = raw.lower()

    def invalid() -> NameRecord:
        return NameRecord(raw, "", wildcard, False, False)

    try:
        fqdn = idna.encode(raw, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return invalid()
    labels = fqdn.split(".")
    if any(not label for label in labels):
        return invalid()
    registrable = _registrable(fqdn)
    if not registrable:
        return invalid()
    idn = any(label.startswith("xn--") for label in labels)
    return NameRecord(fqdn, registrable, wildcard, idn, True)
