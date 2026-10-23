import asyncio

import pytest_asyncio

from dnsserver import DnsServer
from hakapik.resolve import Resolver, addresses

NAME = "login.example.com"
DATA = {
    (NAME, "A"): ("NOERROR", ["1.2.3.4"], 300),
    (NAME, "CNAME"): ("NOERROR", ["cdn.example.net."], 60),
    (NAME, "NS"): ("NOERROR", ["ns1.example.com."], 3600),
    (NAME, "MX"): ("NOERROR", ["10 mail.example.com."], 3600),
    (NAME, "TXT"): ("NOERROR", ['"v=spf1 -all"'], 3600),
    ("example.com", "NS"): ("NOERROR", ["ns1.example.com."], 3600),
    ("4.3.2.1.in-addr.arpa", "PTR"): ("NOERROR", ["host.example.com."], 120),
    ("slow.example.com", "A"): ("NOERROR", ["1.2.3.4"], 300),
}


@pytest_asyncio.fixture
async def dns_server():
    loop = asyncio.get_running_loop()
    transport, server = await loop.create_datagram_endpoint(
        lambda: DnsServer(DATA, drop={"slow.example.com"}), local_addr=("127.0.0.1", 0))
    try:
        yield server
    finally:
        transport.close()


async def test_records_every_type_and_ptr(dns_server):
    r = Resolver(("127.0.0.1",), port=dns_server.port)
    ans = await r.resolve(NAME, "example.com")
    kinds = {(a.qname, a.rrtype) for a in ans}
    assert {(NAME, t) for t in ("A", "AAAA", "CNAME", "NS", "MX", "TXT")} <= kinds
    assert ("example.com", "NS") in kinds
    assert ("4.3.2.1.in-addr.arpa", "PTR") in kinds
    a = next(x for x in ans if x.rrtype == "A")
    assert a.answers == ("1.2.3.4",) and a.ttl == 300 and a.resolver == "127.0.0.1"
    assert a.rcode == "NOERROR" and a.queried_at.endswith("Z")
    ptr = next(x for x in ans if x.rrtype == "PTR")
    assert ptr.answers == ("host.example.com.",)
    assert addresses(ans, NAME) == ["1.2.3.4"]


async def test_nxdomain_recorded(dns_server):
    r = Resolver(("127.0.0.1",), port=dns_server.port)
    ans = await r.resolve("nope.example.org", "example.org")
    assert ans and all(a.rcode == "NXDOMAIN" and a.answers == () for a in ans)
    assert all(a.resolver == "127.0.0.1" for a in ans)
    assert addresses(ans, "nope.example.org") == []


async def test_timeout_recorded_not_raised(dns_server):
    r = Resolver(("127.0.0.1",), port=dns_server.port, timeout_s=0.5)
    ans = await r.resolve("slow.example.com", "slow.example.com")
    assert len(ans) == 6 and all(a.rcode == "TIMEOUT" and a.answers == () for a in ans)
    assert all(a.resolver == "127.0.0.1" and a.ttl is None for a in ans)


async def test_empty_type_is_noerror(dns_server):
    r = Resolver(("127.0.0.1",), port=dns_server.port)
    ans = await r.resolve(NAME, "example.com")
    aaaa = next(x for x in ans if x.rrtype == "AAAA")
    assert aaaa.rcode == "NOERROR" and aaaa.answers == () and aaaa.ttl is None
