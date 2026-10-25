import asyncio
import json
import uuid

import aiohttp


class Wire:
    def __init__(self, session, socket):
        self.session, self.socket = session, socket
        self.pending = {}
        self.events = asyncio.Queue(maxsize=128)
        self.reader = asyncio.create_task(self.read())

    @property
    def closed(self):
        return self.socket.closed

    async def read(self):
        try:
            async for msg in self.socket:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    continue
                value = json.loads(msg.data)
                rid = value.get("id")
                if rid in self.pending:
                    future = self.pending.pop(rid)
                    if not future.done():
                        future.set_result(value)
                else:
                    if self.events.full():
                        self.events.get_nowait()
                    self.events.put_nowait(value)
        finally:
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(ConnectionError("Connection closed"))
            self.pending.clear()

    async def close(self):
        await self.socket.close()
        self.reader.cancel()
        await asyncio.gather(self.reader, return_exceptions=True)
        await self.session.close()


class Gateway:
    def __init__(self, url, origin):
        self.url, self.origin, self.wire = url, origin, None

    @property
    def closed(self):
        return self.wire is None or self.wire.closed

    async def connect(self):
        session = aiohttp.ClientSession()
        try:
            socket = await session.ws_connect(
                self.url,
                heartbeat=20,
                max_msg_size=8 * 1024 * 1024,
                headers={
                    "x-forwarded-user": "tom-controller",
                    "x-forwarded-proto": "https",
                    "x-forwarded-host": self.origin.removeprefix("https://"),
                    "x-forwarded-for": "198.51.100.10",
                    "Origin": self.origin,
                },
            )
            challenge = await asyncio.wait_for(socket.receive_json(), 30)
            if challenge.get("event") != "connect.challenge":
                raise RuntimeError("Unexpected gateway handshake")
            self.wire = Wire(session, socket)
            await self.request(
                "connect",
                {
                    "minProtocol": 4,
                    "maxProtocol": 4,
                    "client": {
                        "id": "openclaw-control-ui",
                        "version": "tom-0.1.0",
                        "platform": "linux",
                        "mode": "webchat",
                    },
                    "role": "operator",
                    "scopes": [],
                    "caps": ["tool-events"],
                },
                timeout=30,
            )
        except BaseException:
            await session.close()
            raise

    async def request(self, method, params=None, timeout=30):
        rid = uuid.uuid4().hex
        future = asyncio.get_running_loop().create_future()
        self.wire.pending[rid] = future
        try:
            await self.wire.socket.send_json(
                {"type": "req", "id": rid, "method": method, "params": params or {}}
            )
            response = await asyncio.wait_for(future, timeout)
            if not response.get("ok"):
                error = response.get("error", {})
                raise RuntimeError(f"Gateway {method}: {error.get('message', 'request refused')}")
            return response.get("payload", {})
        finally:
            self.wire.pending.pop(rid, None)

    async def close(self):
        if self.wire:
            await self.wire.close()


class CDP:
    def __init__(self, wire):
        self.wire = wire
        self.next_id = 0

    @classmethod
    async def connect(cls, base_url, target=None):
        session = aiohttp.ClientSession()
        try:
            async with session.get(
                base_url + "/json/list", timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                pages = [x for x in await response.json() if x.get("type") == "page"]
            if target:
                page = next((p for p in pages if p["id"] == target), None)
            else:
                page = pages[0] if pages else None
            if page is None:
                raise ValueError("Browser tab was not found")
            # Rewrite the endpoint to the known instance host; never follow an arbitrary CDP URL.
            from urllib.parse import urlsplit

            endpoint = (
                base_url.replace("http://", "ws://") + urlsplit(page["webSocketDebuggerUrl"]).path
            )
            socket = await session.ws_connect(endpoint, max_msg_size=8 * 1024 * 1024)
            return cls(Wire(session, socket))
        except BaseException:
            await session.close()
            raise

    async def call(self, method, params=None):
        self.next_id += 1
        rid = self.next_id
        future = asyncio.get_running_loop().create_future()
        self.wire.pending[rid] = future
        try:
            await self.wire.socket.send_json({"id": rid, "method": method, "params": params or {}})
            response = await asyncio.wait_for(future, 15)
            if "error" in response:
                raise RuntimeError("Browser operation was refused")
            return response.get("result", {})
        finally:
            self.wire.pending.pop(rid, None)

    async def close(self):
        await self.wire.close()
