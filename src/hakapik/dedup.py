"""Certificate dedup key."""

import hashlib


def cert_key(issuer_dn_der: bytes, serial: bytes) -> bytes:
    """Return the 32-byte dedup key for an (issuer DN, serial) pair."""
    return hashlib.sha256(issuer_dn_der + serial).digest()
