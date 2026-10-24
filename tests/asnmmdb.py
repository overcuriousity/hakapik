"""A GeoLite2-ASN style ``.mmdb`` writer for ASN tests, as a pytest fixture."""

import netaddr
import pytest
from mmdb_writer import MMDBWriter


@pytest.fixture
def asn_mmdb(tmp_path):
    """``asn_mmdb(network="1.2.3.0/24", asn=64500)``: write ``tmp_path/asn.mmdb``.

    The network maps to ``asn`` and organisation "Example AS"; calling it again
    overwrites the same file. Returns the path.
    """

    def write(network: str = "1.2.3.0/24", asn: int = 64500):
        w = MMDBWriter(ip_version=6, database_type="GeoLite2-ASN", ipv4_compatible=True)
        w.insert_network(netaddr.IPSet([network]), {
            "autonomous_system_number": asn,
            "autonomous_system_organization": "Example AS",
        })
        path = tmp_path / "asn.mmdb"
        w.to_db_file(str(path))
        return path

    return write
