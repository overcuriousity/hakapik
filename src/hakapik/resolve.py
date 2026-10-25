"""DNS resolver that records every answer (spec 5.4: private passive DNS).

Each query yields exactly one DnsAnswer, whatever happens: failures are
recorded as an rcode, never raised.
"""

import asyncio
import logging
from datetime import UTC, datetime

import dns.asyncresolver
import dns.exception
import dns.rcode
import dns.resolver
import dns.reversename

from hakapik.protocol import DnsAnswer

log = logging.getLogger(__name__)

_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class Resolver:
    """One dnspython resolver per nameserver, tried in order.

    dnspython does not say which server produced an NXDOMAIN, so each server
    gets its own resolver: the recorded ``resolver`` is then the one that
    actually answered.

    Servers are tried one after another, never in parallel, so the first
    configured server answers whenever it can. Each server gets at most
    ``timeout_s``, and one query at most ``query_deadline_s`` across all
    servers; ``resolve`` runs two rounds (names, then PTRs), so it takes at
    most 2 * query_deadline_s (config.py folds this into the lease check).
    """

    def __init__(self, nameservers: tuple[str, ...] = (), *, port: int = 53,
                 timeout_s: float = 5.0, query_deadline_s: float = 10.0):
        if not nameservers:
            try:
                system = dns.resolver.Resolver(configure=True).nameservers
            except dns.resolver.NoResolverConfiguration:
                system = []
            nameservers = tuple(str(ns) for ns in system)
        if not nameservers:
            raise ValueError("no DNS nameservers configured")
        self._servers = nameservers
        self._timeout_s = timeout_s
        self._deadline_s = query_deadline_s
        self._resolvers = []
        for ns in nameservers:
            res = dns.asyncresolver.Resolver(configure=False)
            res.nameservers = [ns]
            res.port = port
            res.lifetime = timeout_s
            res.timeout = timeout_s
            self._resolvers.append(res)

    async def _ask(self, res, server, qname, rrtype, queried_at,
                   lifetime: float) -> DnsAnswer:
        """Ask one server. rcode TIMEOUT/SERVFAIL/ERROR... mean 'try the next'."""
        rcode, ttl, answers = "NOERROR", None, ()
        try:
            ans = await res.resolve(qname, rrtype, raise_on_no_answer=False,
                                    lifetime=lifetime)
            if ans.rrset is not None:
                ttl = ans.rrset.ttl
                answers = tuple(sorted(r.to_text() for r in ans.rrset))
        except dns.resolver.NXDOMAIN:
            rcode = "NXDOMAIN"
        except dns.resolver.YXDOMAIN:
            rcode = "YXDOMAIN"
        except dns.resolver.NoNameservers as e:
            # SERVFAIL/REFUSED carry a response; I/O or parse failures do not.
            rcode = "ERROR"
            for _ns, _tcp, _port, _exc, response in e.kwargs.get("errors", ()):
                if response is not None:
                    rcode = dns.rcode.to_text(response.rcode())
                    break
        except dns.resolver.LifetimeTimeout:
            rcode = "TIMEOUT"
        except Exception:
            log.warning("unexpected error resolving %s %s", qname, rrtype, exc_info=True)
            rcode = "ERROR"
        return DnsAnswer(qname, rrtype, rcode, ttl, answers, server, queried_at)

    async def _query(self, qname: str, rrtype: str) -> DnsAnswer:
        queried_at = _now()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._deadline_s
        failures = []
        for res, server in zip(self._resolvers, self._servers):
            remaining = deadline - loop.time()
            if remaining <= 0 and failures:
                break
            a = await self._ask(res, server, qname, rrtype, queried_at,
                                min(self._timeout_s, max(remaining, 0.0)))
            if a.rcode in ("NOERROR", "NXDOMAIN", "YXDOMAIN"):
                return a
            failures.append(a)
        # Every server failed: prefer one that actually answered (SERVFAIL...).
        return next((a for a in failures if a.rcode not in ("TIMEOUT", "ERROR")),
                    failures[0])

    async def resolve(self, fqdn: str, registrable: str) -> tuple[DnsAnswer, ...]:
        # DNS names are case-insensitive; one spelling keeps qname lookups exact.
        fqdn, registrable = fqdn.rstrip(".").lower(), registrable.rstrip(".").lower()
        queries = [(fqdn, t) for t in _TYPES]
        if registrable != fqdn:
            queries.append((registrable, "NS"))
        first = tuple(await asyncio.gather(*(self._query(n, t) for n, t in queries)))
        ptr_names = sorted({
            dns.reversename.from_address(ip).to_text(omit_final_dot=True)
            for ip in addresses(first, fqdn)
        })
        ptrs = await asyncio.gather(*(self._query(n, "PTR") for n in ptr_names))
        return (*first, *ptrs)


def addresses(answers: tuple[DnsAnswer, ...], fqdn: str) -> list[str]:
    """A then AAAA addresses for fqdn (any case, trailing dot), in answer order."""
    fqdn = fqdn.rstrip(".").lower()
    return [ip for t in ("A", "AAAA") for a in answers
            if a.qname == fqdn and a.rrtype == t for ip in a.answers]
