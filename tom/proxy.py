"""Authenticated CONNECT proxy. DNS is checked then the exact approved IP is dialled."""

import asyncio
import base64
import hmac
import ipaddress
import socket


def public_ip(address):
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    # is_global excludes RFC1918, loopback, CGNAT, link-local, multicast and reserved ranges.
    return ip.is_global and not ip.is_multicast


async def resolve_public(host):
    if not host or len(host) > 253:
        raise ValueError("Invalid hostname")
    host = host.rstrip(".").encode("idna").decode("ascii")
    infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    addresses = sorted({x[4][0] for x in infos})
    if not addresses or not all(public_ip(x) for x in addresses):
        raise ValueError("Private or reserved destinations are blocked")
    return addresses


class EgressProxy:
    def __init__(self, store):
        self.store = store
        self.server = None
        self.tasks = set()
        self.connections = asyncio.Semaphore(64)

    def authorized(self, headers):
        raw = headers.get("proxy-authorization", "")
        try:
            if not raw.startswith("Basic "):
                return False
            iid, token = base64.b64decode(raw[6:], validate=True).decode().split(":", 1)
            instance = self.store.instance(iid)
            if instance is None or instance["state"] not in {"starting", "running", "human"}:
                return False
            expected = self.store.get_secret(iid, "internal/proxy-token") or ""
            return bool(expected) and hmac.compare_digest(token, expected)
        except (ValueError, UnicodeError):
            return False

    async def start(self, host="0.0.0.0", port=8888):
        self.server = await asyncio.start_server(self.handle, host, port, limit=16384)

    async def close(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        upstream = None
        try:
            async with asyncio.timeout(900), self.connections:
                block = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
                if len(block) > 16384:
                    raise ValueError("Headers too large")
                lines = block.decode("ascii").split("\r\n")
                method, target, version = lines[0].split(" ")
                headers = {}
                for line in lines[1:]:
                    if line:
                        k, v = line.split(":", 1)
                        if k.lower() in headers:
                            raise ValueError("Duplicate header")
                        headers[k.lower()] = v.strip()
                if not self.authorized(headers):
                    writer.write(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                        b'Proxy-Authenticate: Basic realm="Tom"\r\nContent-Length: 0\r\n\r\n'
                    )
                    await writer.drain()
                    return
                if method != "CONNECT" or version not in {"HTTP/1.0", "HTTP/1.1"}:
                    raise ValueError("Only HTTPS CONNECT is allowed")
                host, port = target.rsplit(":", 1)
                host = host.strip("[]")
                if port != "443":
                    raise ValueError("Only port 443 is allowed")
                addresses = await resolve_public(host)
                # Passing a literal address prevents a second DNS lookup/rebinding at connection time.
                addresses.sort(key=lambda a: ipaddress.ip_address(a).version)
                for address in addresses[:8]:
                    try:
                        remote_reader, upstream = await asyncio.wait_for(
                            asyncio.open_connection(address, 443), 10
                        )
                        break
                    except OSError:
                        continue
                if upstream is None:
                    raise OSError("No approved destination address could be reached")
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()

                async def relay(src, dst):
                    while chunk := await src.read(65536):
                        dst.write(chunk)
                        await dst.drain()

                pipes = [
                    asyncio.create_task(relay(reader, upstream)),
                    asyncio.create_task(relay(remote_reader, writer)),
                ]
                try:
                    await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for p in pipes:
                        p.cancel()
                    await asyncio.gather(*pipes, return_exceptions=True)
        except (
            ValueError,
            UnicodeError,
            OSError,
            asyncio.TimeoutError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
        ):
            if upstream is None:
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        finally:
            if upstream:
                upstream.close()
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            self.tasks.discard(task)
