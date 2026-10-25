import asyncio
import hmac
import json
import logging
import os
from pathlib import Path
import re
import time
import uuid

import aiohttp
from aiohttp import web

from .auth import Auth
from .browser import fill_credential, input_action, navigate
from .config import Config
from .proxy import EgressProxy
from .runtime import Busy, Runtime
from .store import Store
from .wire import CDP
from .dns import GuestDNS

LOG = logging.getLogger("tom")


def safe_instance(store, iid, identity):
    instance = store.instance(iid)
    if not instance or (instance["owner"] != identity.email and not identity.admin):
        raise web.HTTPNotFound(text="Assistant not found")
    return instance


def public_instance(instance, store):
    result = {k: instance[k] for k in ["id", "name", "owner", "state", "control_until"]}
    result["has_model_key"] = "model/openai" in store.secret_names(instance["id"])
    result["credentials"] = [
        n[5:] for n in store.secret_names(instance["id"]) if n.startswith("site/")
    ]
    return result


async def json_body(request):
    if request.content_type != "application/json":
        raise web.HTTPUnsupportedMediaType(text="Use application/json")
    value = await request.json()
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def create_app(config, store, runtime, auth=None):
    auth = auth or Auth(config)

    @web.middleware
    async def middleware(request, handler):
        try:
            if request.path not in {"/healthz", "/", "/app.js", "/style.css", "/api/local-login"}:
                request["identity"] = await auth.identify(request)
                if (
                    request.method not in {"GET", "HEAD"}
                    or request.headers.get("Upgrade", "").lower() == "websocket"
                ):
                    auth.check_origin(request)
            response = await handler(request)
        except Busy as e:
            response = web.json_response({"error": str(e)}, status=409)
        except ValueError as e:
            response = web.json_response({"error": str(e)}, status=400)
        except KeyError:
            response = web.json_response(
                {"error": "Invalid request or unavailable configuration"}, status=400
            )
        except web.HTTPException as e:
            response = web.json_response({"error": e.text}, status=e.status)
        except Exception:
            if os.getenv("TOM_INTEGRATION_DIAGNOSTICS") == "1":
                LOG.exception("Disposable integration request failed")
            LOG.error("Request failed: %s %s", request.method, request.path)
            response = web.json_response(
                {"error": "Operation failed. Run tom logs for diagnostics."}, status=502
            )
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
            }
        )
        if request.path.startswith("/instances/") and "/console/" in request.path:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: blob:; connect-src 'self'; frame-src 'self' blob:; "
                "font-src 'self' data:; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'"
            )
        return response

    app = web.Application(middlewares=[middleware], client_max_size=65536)
    app["config"], app["store"], app["runtime"] = config, store, runtime

    async def page(request):
        names = {"/": "index.html", "/app.js": "app.js", "/style.css": "style.css"}
        return web.FileResponse(Path(__file__).parent / "static" / names[request.path])

    async def health(request):
        return web.json_response({"ok": True})

    async def local_login(request):
        if config.auth_mode != "local":
            raise web.HTTPNotFound()
        # Development login is available only in the explicit local-auth configuration.
        body = await json_body(request)
        if not hmac.compare_digest(str(body.get("token", "")), config.local_token):
            raise web.HTTPUnauthorized(text="Invalid local token")
        response = web.json_response({"ok": True})
        response.set_cookie("tom_local", config.local_token, httponly=True, samesite="Strict")
        return response

    async def me(request):
        identity = request["identity"]
        return web.json_response(
            {
                "email": identity.email,
                "admin": identity.admin,
                "max_active": config.max_active,
                "model": config.model,
                "invited_users": config.users if identity.admin else [],
            }
        )

    async def maintenance(request):
        if not auth.unix_admin(request):
            raise web.HTTPForbidden(text="Maintenance requires local Unix-socket administration")
        body = await json_body(request)
        runtime.maintenance = body.get("enabled") is True
        return web.json_response({"ok": True})

    async def instances(request):
        identity = request["identity"]
        if request.method == "GET":
            return web.json_response(
                [
                    public_instance(x, store)
                    for x in store.all_instances()
                    if x["owner"] == identity.email or identity.admin
                ]
            )
        if not identity.admin:
            raise web.HTTPForbidden(text="Only the administrator can create assistants")
        body = await json_body(request)
        owner, name = str(body.get("owner", "")).lower(), str(body.get("name", "")).strip()
        if owner not in config.users or not 1 <= len(name) <= 80:
            raise ValueError("Choose an invited owner and a short name")
        if len(store.all_instances()) >= config.max_instances:
            raise Busy("Saved assistant limit reached")
        instance = store.create_instance(owner, name)
        # A fresh instance receives a separate encrypted reference; no shared browser or memory.
        default_key = store.get_secret("system", "default-openai")
        if default_key:
            store.set_secret(instance["id"], "model/openai", default_key)
        store.audit(identity.email, "instance.create", instance["id"])
        return web.json_response(public_instance(instance, store), status=201)

    def selected(request):
        return safe_instance(store, request.match_info["iid"], request["identity"])

    def control(request, instance, token):
        expected = store.get_secret(instance["id"], "internal/control-token") or ""
        if (
            instance["state"] != "human"
            or instance["control_owner"] != request["identity"].email
            or not instance["control_until"]
            or instance["control_until"] < time.time()
            or not token
            or not hmac.compare_digest(expected, str(token))
        ):
            raise web.HTTPForbidden(text="Take browser control in this tab first")

    async def lifecycle(request):
        instance = selected(request)
        action = request.match_info["action"]
        if action == "start":
            await runtime.start(instance["id"])
        elif action == "stop":
            await runtime.stop(instance["id"])
        elif action == "take-control":
            await runtime.take_control(instance["id"], request["identity"].email)
            token = uuid.uuid4().hex + uuid.uuid4().hex
            store.set_secret(instance["id"], "internal/control-token", token)
            return web.json_response({"token": token})
        elif action == "release-control":
            control(request, instance, request.headers.get("X-Tom-Control"))
            await runtime.release_control(instance["id"], request["identity"].email)
            store.set_secret(instance["id"], "internal/control-token", "")
        else:
            raise web.HTTPNotFound()
        store.audit(request["identity"].email, "instance." + action, instance["id"])
        return web.json_response({"ok": True})

    async def jobs(request):
        instance = selected(request)
        if request.method == "GET":
            return web.json_response(store.jobs(instance["id"]))
        body = await json_body(request)
        message, job_id = body.get("message", ""), body.get("id", "")
        if not isinstance(message, str) or not 1 <= len(message.strip()) <= 12000:
            raise ValueError("Enter a message up to 12,000 characters")
        uuid.UUID(job_id)
        if len(store.queued()) >= 100:
            raise Busy("Message queue is full")
        return web.json_response(store.enqueue(instance["id"], message.strip(), job_id), status=202)

    async def history(request):
        instance = selected(request)
        if instance["state"] != "running":
            return web.json_response({"messages": [], "available": False})
        gateway = await runtime.gateway(instance["id"])
        result = await gateway.request(
            "chat.history", {"sessionKey": "agent:main:main", "limit": 50}
        )
        return web.json_response(result)

    async def memory(request):
        instance = selected(request)
        path = config.data_dir / "instances" / instance["id"] / "state/workspace/MEMORY.md"
        # Only this fixed file can be read, and a symlink cannot escape its workspace.
        if not path.exists():
            return web.json_response({"text": "# Memory\n\n"})
        # Walk directory descriptors too: a symlink in an intermediate directory cannot escape.
        parent = os.open(
            config.data_dir / "instances" / instance["id"],
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            for part in ["state", "workspace"]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open("MEMORY.md", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd) as f:
                text = f.read(65537)
        finally:
            os.close(parent)
        if len(text) > 65536:
            raise ValueError("Memory file exceeds the viewer limit")
        return web.json_response({"text": text})

    async def credentials(request):
        instance = selected(request)
        body = await json_body(request)
        if body.get("kind") == "openai":
            value = body.get("value", "")
            if not isinstance(value, str) or not 10 <= len(value) <= 4096:
                raise ValueError("Enter an API key")
            store.set_secret(instance["id"], "model/openai", value)
        elif body.get("kind") == "website":
            host = body.get("host", "").lower()
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
                raise ValueError("Use a hostname without a scheme or path")
            if any(
                not isinstance(body.get(k), str) or len(body[k]) > 4096
                for k in ["username", "password"]
            ):
                raise ValueError("Enter a username and password")
            store.set_secret(
                instance["id"],
                "site/" + host,
                {"host": host, "username": body["username"], "password": body["password"]},
            )
        else:
            raise ValueError("Unsupported credential type")
        store.audit(request["identity"].email, "credential.saved", instance["id"])
        return web.json_response({"ok": True})

    def browser_url(instance):
        return f"http://{runtime.addresses(instance)['browser']}:9223"

    async def tabs(request):
        instance = selected(request)
        if instance["state"] not in {"running", "human"}:
            return web.json_response([])
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.get(browser_url(instance) + "/json/list") as response:
                data = await response.json()
        return web.json_response(
            [
                {k: x.get(k, "") for k in ["id", "title", "url"]}
                for x in data
                if x.get("type") == "page"
            ]
        )

    async def browser_action_locked(request):
        instance = selected(request)
        control(request, instance, request.headers.get("X-Tom-Control"))
        body = await json_body(request)
        cdp = await CDP.connect(browser_url(instance), body.get("target"))
        try:
            if body.get("type") == "navigate":
                await navigate(cdp, body.get("url", ""))
            elif body.get("type") == "fill-credential":
                credential = store.get_secret(instance["id"], "site/" + body.get("host", ""))
                if not credential:
                    raise ValueError("Saved credential not found")
                await fill_credential(
                    cdp, credential, body.get("username_selector"), body.get("password_selector")
                )
                store.audit(request["identity"].email, "credential.filled", instance["id"])
            else:
                await input_action(cdp, body)
        finally:
            await cdp.close()
        store.update(instance["id"], touched=time.time())
        return web.json_response({"ok": True})

    async def browser_action(request):
        async with runtime.lock:
            return await browser_action_locked(request)

    async def browser_stream(request):
        instance = selected(request)
        if instance["state"] not in {"running", "human"}:
            raise Busy("Start the assistant first")
        cdp = await CDP.connect(browser_url(instance), request.query.get("target"))
        socket = web.WebSocketResponse(heartbeat=20, max_msg_size=8192)
        await socket.prepare(request)
        try:
            await cdp.call("Page.enable")
            initial = await cdp.call("Page.captureScreenshot", {"format": "jpeg", "quality": 55})
            await socket.send_json({"type": "frame", "data": initial["data"]})
            await cdp.call(
                "Page.startScreencast",
                {
                    "format": "jpeg",
                    "quality": 55,
                    "maxWidth": 1280,
                    "maxHeight": 800,
                    "everyNthFrame": 2,
                },
            )

            async def frames():
                last_frame = 0
                while True:
                    event = await cdp.wire.events.get()
                    if event.get("method") == "Page.screencastFrame":
                        params = event["params"]
                        await asyncio.sleep(max(0, 0.2 - (time.monotonic() - last_frame)))
                        await socket.send_json({"type": "frame", "data": params["data"]})
                        last_frame = time.monotonic()
                        await cdp.call(
                            "Page.screencastFrameAck", {"sessionId": params["sessionId"]}
                        )

            sender = asyncio.create_task(frames())

            async def recheck():
                while True:
                    await asyncio.sleep(30)
                    try:
                        await auth.identify(request)
                        if selected(request)["state"] not in {"running", "human"}:
                            break
                    except web.HTTPException:
                        break
                await socket.close(code=1008, message=b"Access expired")

            watcher = asyncio.create_task(recheck())
            try:
                async for msg in socket:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        try:
                            async with runtime.lock:
                                action = json.loads(msg.data)
                                latest = selected(request)
                                control(request, latest, action.pop("token", ""))
                                await input_action(cdp, action)
                                store.update(instance["id"], touched=time.time())
                        except (ValueError, KeyError, web.HTTPException):
                            await socket.send_json(
                                {"error": "Browser input requires valid control in this tab"}
                            )
            finally:
                sender.cancel()
                watcher.cancel()
                await asyncio.gather(sender, watcher, return_exceptions=True)
        finally:
            await cdp.close()
            await socket.close()
        return socket

    async def approvals(request):
        instance = selected(request)
        gateway = await runtime.gateway(instance["id"])
        if request.method == "GET":
            return web.json_response(await gateway.request("exec.approval.list", {}))
        body = await json_body(request)
        if body.get("decision") not in {"allow-once", "deny"}:
            raise ValueError("Choose one-time approval or refusal")
        return web.json_response(
            await gateway.request(
                "exec.approval.resolve", {"id": body["id"], "decision": body["decision"]}
            )
        )

    async def console_launch(request):
        instance = selected(request)
        if instance["state"] != "running":
            raise Busy("Start the assistant and give back browser control first")
        return web.json_response({"url": await runtime.dashboard_url(instance["id"])})

    async def console_proxy(request):
        instance = selected(request)
        if instance["state"] != "running":
            raise Busy("The assistant is stopped or paused for browser control")
        addr = runtime.addresses(instance)
        prefix = f"/instances/{instance['id']}/console"
        headers = {
            "x-forwarded-user": "tom-controller",
            "x-forwarded-proto": "https",
            "x-forwarded-host": config.public_origin.split("//", 1)[1],
            "x-forwarded-for": "198.51.100.10",
            "Origin": config.public_origin,
        }
        gateway_url = f"http://{addr['gateway']}:18789"
        if request.headers.get("Upgrade", "").lower() == "websocket":
            auth.check_origin(request)
            async with aiohttp.ClientSession() as session:
                upstream = await session.ws_connect(
                    gateway_url, headers=headers, max_msg_size=25 * 1024 * 1024
                )
                downstream = web.WebSocketResponse(heartbeat=20, max_msg_size=25 * 1024 * 1024)
                await downstream.prepare(request)
                runtime.console_viewers[instance["id"]] = (
                    runtime.console_viewers.get(instance["id"], 0) + 1
                )

                async def relay(source, destination):
                    async for message in source:
                        if message.type == aiohttp.WSMsgType.TEXT:
                            await destination.send_str(message.data)
                        elif message.type == aiohttp.WSMsgType.BINARY:
                            await destination.send_bytes(message.data)

                async def recheck():
                    while True:
                        await asyncio.sleep(30)
                        await auth.identify(request)
                        if selected(request)["state"] != "running":
                            return

                tasks = [
                    asyncio.create_task(relay(upstream, downstream)),
                    asyncio.create_task(relay(downstream, upstream)),
                    asyncio.create_task(recheck()),
                ]
                try:
                    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    await upstream.close()
                    await downstream.close()
                    runtime.console_viewers[instance["id"]] -= 1
                return downstream
        path = prefix + "/" + request.match_info.get("tail", "")
        if request.query_string:
            path += "?" + request.query_string
        if request.content_type:
            headers["Content-Type"] = request.content_type
        async with aiohttp.ClientSession() as session:
            async with session.request(
                request.method,
                gateway_url + path,
                headers=headers,
                data=await request.read(),
                allow_redirects=False,
            ) as response:
                copied = {
                    k: v
                    for k, v in response.headers.items()
                    if k.lower() in {"content-type", "location"}
                }
                return web.Response(
                    status=response.status, body=await response.read(), headers=copied
                )

    app.add_routes(
        [
            web.get("/", page),
            web.get("/app.js", page),
            web.get("/style.css", page),
            web.get("/healthz", health),
            web.post("/api/local-login", local_login),
            web.get("/api/me", me),
            web.post("/api/admin/maintenance", maintenance),
            web.get("/api/instances", instances),
            web.post("/api/instances", instances),
            web.get("/api/instances/{iid}/jobs", jobs),
            web.post("/api/instances/{iid}/jobs", jobs),
            web.get("/api/instances/{iid}/history", history),
            web.get("/api/instances/{iid}/memory", memory),
            web.post("/api/instances/{iid}/credentials", credentials),
            web.get("/api/instances/{iid}/tabs", tabs),
            web.post("/api/instances/{iid}/browser", browser_action),
            web.get("/api/instances/{iid}/stream", browser_stream),
            web.get("/api/instances/{iid}/approvals", approvals),
            web.post("/api/instances/{iid}/approvals", approvals),
            web.post("/api/instances/{iid}/console-launch", console_launch),
            web.route("*", "/instances/{iid}/console/{tail:.*}", console_proxy),
            web.post("/api/instances/{iid}/{action}", lifecycle),
        ]
    )
    return app


async def scheduler(config, store, runtime):
    while True:
        try:
            for instance in store.all_instances():
                if instance["state"] == "human" and instance["control_until"] < time.time():
                    # An expired human lease stops execution; it never silently resumes automation.
                    await runtime.stop(instance["id"])
                if (
                    instance["state"] == "running"
                    and time.time() - instance["touched"] > config.idle_seconds
                    and not runtime.console_viewers.get(instance["id"])
                ):
                    await runtime.stop(instance["id"])
            queued = store.queued()
            for job in queued:
                if store.instance(job["instance"])["state"] == "human":
                    continue
                try:
                    await runtime.start(job["instance"])
                except Busy:
                    continue
                store.finish_job(job["id"], "running")
                try:
                    gateway = await runtime.gateway(job["instance"])
                    ack = await gateway.request(
                        "chat.send",
                        {
                            "sessionKey": "agent:main:main",
                            "message": job["message"],
                            "idempotencyKey": job["id"],
                            "timeoutMs": 300000,
                        },
                    )
                    run_id = ack.get("runId")
                    if not run_id:
                        raise RuntimeError("Gateway did not acknowledge a run ID")
                    result = await gateway.request(
                        "agent.wait", {"runId": run_id, "timeoutMs": 300000}, timeout=310
                    )
                    if result.get("status") in {"timeout", "error", "aborted"}:
                        raise RuntimeError(
                            "Run did not complete; inspect its conversation before retrying"
                        )
                    store.finish_job(
                        job["id"], "complete", "Finished. Open the conversation for the result."
                    )
                except Exception:
                    state = (
                        "interrupted"
                        if store.instance(job["instance"])["state"] == "human"
                        else "failed"
                    )
                    store.finish_job(
                        job["id"],
                        state,
                        "Run stopped or failed. Inspect the conversation before retrying.",
                    )
                store.update(job["instance"], touched=time.time())
                break
        except asyncio.CancelledError:
            raise
        except Exception:
            LOG.error("Worker could not complete an operation; inspect runtime health")
            await asyncio.sleep(5)
        await asyncio.sleep(1)


async def main():
    config = Config.load(os.getenv("TOM_CONFIG", "/opt/tom/config.json"))
    key = Path(os.getenv("TOM_VAULT_KEY", "/opt/tom/secrets/vault.key")).read_bytes()
    store = Store(config.data_dir, key)
    runtime = Runtime(config, store)
    if config.auth_mode == "cloudflare":
        # Docker may restore the management service before systemd applies its host rule.
        # /run is cleared on reboot, so a stale marker cannot authorize the next boot.
        while not Path("/run/tom/network-ready").exists():
            await asyncio.sleep(1)
    await runtime.initialize()
    proxy = EgressProxy(store)
    await proxy.start()
    _, guest_dns = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: GuestDNS(store, runtime), local_addr=("0.0.0.0", 53)
    )

    async def resolve(request):
        # This listener is private. A capability is bound to one existing instance and key.
        body = await json_body(request)
        iid = body.get("instance")
        instance = store.instance(iid)
        supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
        expected = store.get_secret(iid, "internal/proxy-token") or ""
        if (
            not instance
            or request.remote != runtime.addresses(instance)["gateway"]
            or not expected
            or not hmac.compare_digest(supplied, expected)
        ):
            raise web.HTTPForbidden()
        value = store.get_secret(iid, "model/openai")
        if not value:
            raise web.HTTPNotFound()
        return web.json_response({"value": value}, headers={"Cache-Control": "no-store"})

    broker = web.Application(client_max_size=4096)
    broker.router.add_post("/resolve", resolve)
    broker_runner = web.AppRunner(broker, access_log=None)
    await broker_runner.setup()
    await web.TCPSite(broker_runner, "0.0.0.0", 8081).start()
    app = create_app(config, store, runtime)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", 8080).start()
    admin_socket = runtime.runtime_dir / "admin.sock"
    admin_socket.unlink(missing_ok=True)
    await web.UnixSite(runner, str(admin_socket)).start()
    os.chmod(admin_socket, 0o600)
    worker = asyncio.create_task(scheduler(config, store, runtime))
    LOG.warning("Tom ready; %s active slot(s)", config.max_active)
    try:
        await asyncio.Event().wait()
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
        await runtime.close()
        await proxy.close()
        await guest_dns.close()
        await runner.cleanup()
        await broker_runner.cleanup()
        store.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    asyncio.run(main())
