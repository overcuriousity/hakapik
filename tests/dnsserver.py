"""A tiny DNS responder (UDP and TCP) for resolver tests, as a pytest fixture."""

import asyncio
import contextlib

import dns.flags
import dns.message
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest_asyncio


class DnsServer(asyncio.DatagramProtocol):
    """Serves ``{(qname, rrtype): (rcode, [rdata text], ttl)}``.

    A known name asked for a missing type gets NOERROR with no data; an
    unknown name gets NXDOMAIN; names in ``drop`` get no reply at all; names
    in ``truncate`` get an empty truncated (TC) reply over UDP and the full
    answer only over TCP.
    """

    def __init__(self, data, drop=(), truncate=()):
        self.data = data
        self.drop = set(drop)
        self.truncate = set(truncate)
        self.port = 0
        self.transport = None
        self.tcp_queries: list[str] = []

    def connection_made(self, transport):
        self.transport = transport
        self.port = transport.get_extra_info("sockname")[1]

    def reply(self, wire: bytes, tcp: bool) -> bytes | None:
        query = dns.message.from_wire(wire)
        question = query.question[0]
        name = question.name.to_text(omit_final_dot=True).lower()
        if name in self.drop:
            return None
        rrtype = dns.rdatatype.to_text(question.rdtype)
        reply = dns.message.make_response(query)
        if tcp:
            self.tcp_queries.append(name)
        elif name in self.truncate:
            reply.flags |= dns.flags.TC
            return reply.to_wire()
        if (name, rrtype) in self.data:
            rcode, texts, ttl = self.data[(name, rrtype)]
            reply.set_rcode(dns.rcode.from_text(rcode))
            if texts:
                reply.answer.append(dns.rrset.from_text_list(
                    question.name, ttl, "IN", rrtype, texts))
        elif not any(n == name for n, _ in self.data):
            reply.set_rcode(dns.rcode.NXDOMAIN)
        return reply.to_wire()

    def datagram_received(self, wire, addr):
        out = self.reply(wire, tcp=False)
        if out is not None:
            self.transport.sendto(out, addr)

    async def handle_tcp(self, reader, writer):
        try:
            while True:
                size = int.from_bytes(await reader.readexactly(2), "big")
                out = self.reply(await reader.readexactly(size), tcp=True)
                if out is not None:
                    writer.write(len(out).to_bytes(2, "big") + out)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


@pytest_asyncio.fixture
async def dns_server_factory():
    """``await start(data, drop=(), truncate=())``: a DnsServer on 127.0.0.1.

    UDP and TCP listen on the same port (``server.port``); all are closed at
    teardown.
    """
    loop = asyncio.get_running_loop()
    closers = []

    async def start(data, drop=(), truncate=()):
        server = DnsServer(data, drop, truncate)
        tcp = await asyncio.start_server(server.handle_tcp, "127.0.0.1", 0)
        closers.append(tcp)
        port = tcp.sockets[0].getsockname()[1]
        transport, _ = await loop.create_datagram_endpoint(
            lambda: server, local_addr=("127.0.0.1", port))
        closers.append(transport)
        return server

    try:
        yield start
    finally:
        for c in reversed(closers):
            c.close()
            if isinstance(c, asyncio.Server):
                with contextlib.suppress(Exception):
                    await c.wait_closed()
