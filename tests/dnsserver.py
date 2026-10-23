"""A tiny UDP DNS responder for resolver tests."""

import asyncio

import dns.flags
import dns.message
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset


class DnsServer(asyncio.DatagramProtocol):
    """Serves ``{(qname, rrtype): (rcode, [rdata text], ttl)}``.

    A known name asked for a missing type gets NOERROR with no data; an
    unknown name gets NXDOMAIN; names in ``drop`` get no reply at all.
    """

    def __init__(self, data, drop=()):
        self.data = data
        self.drop = set(drop)
        self.port = 0
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.port = transport.get_extra_info("sockname")[1]

    def datagram_received(self, wire, addr):
        query = dns.message.from_wire(wire)
        question = query.question[0]
        name = question.name.to_text(omit_final_dot=True).lower()
        if name in self.drop:
            return
        rrtype = dns.rdatatype.to_text(question.rdtype)
        reply = dns.message.make_response(query)
        if (name, rrtype) in self.data:
            rcode, texts, ttl = self.data[(name, rrtype)]
            reply.set_rcode(dns.rcode.from_text(rcode))
            if texts:
                reply.answer.append(dns.rrset.from_text_list(
                    question.name, ttl, "IN", rrtype, texts))
        elif not any(n == name for n, _ in self.data):
            reply.set_rcode(dns.rcode.NXDOMAIN)
        self.transport.sendto(reply.to_wire(), addr)
