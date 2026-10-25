"""DNS for internal guest networks: own service names and public A/AAAA answers only."""

import asyncio
import ipaddress

from dnslib import DNSRecord, QTYPE, RR, A, AAAA, RCODE

from .proxy import resolve_public


class GuestDNS(asyncio.DatagramProtocol):
    def __init__(self, store, runtime):
        self.store, self.runtime = store, runtime
        self.transport = None
        self.tasks = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if len(data) > 4096 or len(self.tasks) >= 64:
            return
        task = asyncio.create_task(self.answer(data, address))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def answer(self, data, address):
        try:
            request = DNSRecord.parse(data)
            if len(request.questions) != 1:
                return
            reply = request.reply()
            owner = next(
                (
                    i
                    for i in self.store.all_instances()
                    if address[0]
                    in {self.runtime.addresses(i)["gateway"], self.runtime.addresses(i)["browser"]}
                    and i["state"] in {"starting", "running", "human"}
                ),
                None,
            )
            if not owner:
                reply.header.rcode = RCODE.REFUSED
            elif request.q.qtype in {QTYPE.A, QTYPE.AAAA}:
                hostname = str(request.q.qname).rstrip(".").lower()
                own_names = {
                    self.runtime.name(owner["id"], role): self.runtime.addresses(owner)[role]
                    for role in ["gateway", "browser"]
                }
                try:
                    addresses = (
                        [own_names[hostname]]
                        if hostname in own_names
                        else await asyncio.wait_for(resolve_public(hostname), 5)
                    )
                    for value in addresses[:8]:
                        if request.q.qtype == QTYPE.A and ipaddress.ip_address(value).version == 4:
                            reply.add_answer(RR(request.q.qname, QTYPE.A, ttl=30, rdata=A(value)))
                        elif (
                            request.q.qtype == QTYPE.AAAA
                            and ipaddress.ip_address(value).version == 6
                        ):
                            reply.add_answer(
                                RR(request.q.qname, QTYPE.AAAA, ttl=30, rdata=AAAA(value))
                            )
                except ValueError:
                    reply.header.rcode = RCODE.NXDOMAIN
                except (OSError, asyncio.TimeoutError):
                    reply.header.rcode = RCODE.SERVFAIL
            # Other record types get an empty NOERROR answer, allowing clients to fall back to A/AAAA.
            self.transport.sendto(reply.pack(), address)
        except Exception:
            return

    async def close(self):
        self.transport.close()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
