"""DNS resolver that records every answer (spec 5.4: private passive DNS).

Each query yields exactly one DnsAnswer, whatever happens: failures are
recorded as an rcode, never raised.
"""

import asyncio
from datetime import UTC, datetime

import dns.asyncresolver
import dns.exception
import dns.rcode
import dns.resolver
import dns.reversename

from hakapik.protocol import DnsAnswer

_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class Resolver:
    def __init__(self, nameservers: tuple[str, ...] = (), *, port: int = 53,
                 timeout_s: float = 5.0):
        self._res = dns.asyncresolver.Resolver(configure=not nameservers)
        if nameservers:
            self._res.nameservers = list(nameservers)
            self._res.port = port
        self._res.lifetime = timeout_s
        self._res.timeout = timeout_s

    def _first_server(self) -> str:
        return str(self._res.nameservers[0]) if self._res.nameservers else ""

    async def _query(self, qname: str, rrtype: str) -> DnsAnswer:
        queried_at = _now()
        rcode, ttl, answers, server = "NOERROR", None, (), self._first_server()
        try:
            ans = await self._res.resolve(qname, rrtype, raise_on_no_answer=False)
            server = str(ans.nameserver)
            if ans.rrset is not None:
                ttl = ans.rrset.ttl
                answers = tuple(sorted(r.to_text() for r in ans.rrset))
        except dns.resolver.NXDOMAIN:
            rcode = "NXDOMAIN"
        except dns.resolver.NoNameservers as e:
            rcode = "SERVFAIL"
            for ns, _tcp, _port, _exc, response in e.errors():
                server = str(ns)
                if response is not None:
                    rcode = dns.rcode.to_text(response.rcode())
                break
        except dns.resolver.LifetimeTimeout:
            rcode = "TIMEOUT"
        except Exception:
            rcode = "ERROR"
        return DnsAnswer(qname, rrtype, rcode, ttl, answers, server, queried_at)

    async def resolve(self, fqdn: str, registrable: str) -> tuple[DnsAnswer, ...]:
        fqdn, registrable = fqdn.rstrip("."), registrable.rstrip(".")
        queries = [(fqdn, t) for t in _TYPES]
        if registrable != fqdn:
            queries.append((registrable, "NS"))
        first = await asyncio.gather(*(self._query(n, t) for n, t in queries))
        ptr_names = sorted({
            dns.reversename.from_address(ip).to_text(omit_final_dot=True)
            for ip in addresses(first, fqdn)
        })
        ptrs = await asyncio.gather(*(self._query(n, "PTR") for n in ptr_names))
        return (*first, *ptrs)


def addresses(answers: tuple[DnsAnswer, ...], fqdn: str) -> list[str]:
    """A then AAAA addresses for fqdn, in answer order."""
    return [ip for t in ("A", "AAAA") for a in answers
            if a.qname == fqdn and a.rrtype == t for ip in a.answers]
