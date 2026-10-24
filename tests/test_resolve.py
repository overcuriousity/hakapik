import dns.asyncresolver
import dns.resolver
import dns.reversename
import pytest
import pytest_asyncio

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
    ("many.example.com", "A"): ("NOERROR", ["9.9.9.9", "1.1.1.1", "5.5.5.5"], 300),
    ("v6.example.com", "AAAA"): ("NOERROR", ["2001:db8::1"], 300),
    (dns.reversename.from_address("2001:db8::1").to_text(omit_final_dot=True), "PTR"):
        ("NOERROR", ["v6host.example.com."], 120),
    ("big.example.com", "A"): ("NOERROR", ["1.2.3.4"], 300),
}


@pytest_asyncio.fixture
async def dns_server(dns_server_factory):
    return await dns_server_factory(DATA, drop={"slow.example.com"},
                                    truncate={"big.example.com"})


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


async def test_resolver_is_the_server_that_answered(dns_server):
    # Nothing listens on 127.0.0.2 at this port, so the second server answers.
    r = Resolver(("127.0.0.2", "127.0.0.1"), port=dns_server.port, timeout_s=0.5)
    ans = await r.resolve("nope.example.org", "example.org")
    assert all(a.rcode == "NXDOMAIN" and a.resolver == "127.0.0.1" for a in ans)


async def test_servfail_recorded_with_answering_server(dns_server_factory):
    srv = await dns_server_factory({(NAME, "A"): ("SERVFAIL", [], 0)})
    r = Resolver(("127.0.0.1",), port=srv.port)
    ans = await r.resolve(NAME, NAME)
    a = next(x for x in ans if x.rrtype == "A")
    assert a.rcode == "SERVFAIL" and a.resolver == "127.0.0.1" and a.answers == ()


async def test_unexpected_error_is_logged_and_recorded(dns_server, monkeypatch, caplog):
    async def boom(self, *a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", boom)
    r = Resolver(("127.0.0.1",), port=dns_server.port)
    with caplog.at_level("WARNING", logger="hakapik.resolve"):
        ans = await r.resolve(NAME, NAME)
    assert ans and all(a.rcode == "ERROR" for a in ans)
    assert any(NAME in rec.getMessage() and rec.exc_info for rec in caplog.records)


def test_no_nameservers_raises(monkeypatch):
    class Empty:
        nameservers = []

    monkeypatch.setattr(dns.resolver, "Resolver", lambda configure=True: Empty())
    with pytest.raises(ValueError, match="no DNS nameservers configured"):
        Resolver(())

    def unconfigured(configure=True):
        raise dns.resolver.NoResolverConfiguration("no nameservers")

    monkeypatch.setattr(dns.resolver, "Resolver", unconfigured)
    with pytest.raises(ValueError, match="no DNS nameservers configured"):
        Resolver(())


async def test_multiple_addresses_are_sorted(dns_server):
    r = Resolver(("127.0.0.1",), port=dns_server.port)
    ans = await r.resolve("many.example.com", "example.com")
    a = next(x for x in ans if x.rrtype == "A")
    assert a.answers == ("1.1.1.1", "5.5.5.5", "9.9.9.9")
    ptrs = [x.qname for x in ans if x.rrtype == "PTR"]
    assert ptrs == sorted(ptrs) and len(ptrs) == 3


async def test_ipv6_address_gets_an_ip6_arpa_ptr(dns_server):
    r = Resolver(("127.0.0.1",), port=dns_server.port)
    ans = await r.resolve("v6.example.com", "example.com")
    assert addresses(ans, "v6.example.com") == ["2001:db8::1"]
    [ptr] = [x for x in ans if x.rrtype == "PTR"]
    assert ptr.qname.endswith(".8.b.d.0.1.0.0.2.ip6.arpa")
    assert ptr.answers == ("v6host.example.com.",) and ptr.rcode == "NOERROR"


async def test_truncated_udp_reply_falls_back_to_tcp(dns_server):
    r = Resolver(("127.0.0.1",), port=dns_server.port)
    ans = await r.resolve("big.example.com", "example.com")
    a = next(x for x in ans if x.rrtype == "A")
    assert a.rcode == "NOERROR" and a.answers == ("1.2.3.4",)
    assert "big.example.com" in dns_server.tcp_queries


async def test_qname_case_and_trailing_dot_are_normalised(dns_server):
    r = Resolver(("127.0.0.1",), port=dns_server.port)
    ans = await r.resolve("LOGIN.Example.COM.", "Example.COM.")
    assert {a.qname for a in ans if a.rrtype != "PTR"} == {NAME, "example.com"}
    assert addresses(ans, NAME) == ["1.2.3.4"]
