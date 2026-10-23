import hashlib

from hakapik.dedup import cert_key


def test_cert_key_is_sha256_of_issuer_and_serial():
    assert cert_key(b"i", b"s") == hashlib.sha256(b"i" + b"s").digest()
