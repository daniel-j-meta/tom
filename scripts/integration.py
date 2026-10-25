"""Disposable Docker integration checks. No Cloudflare changes or model inference."""

import asyncio
import json
import os
from pathlib import Path
import socket
import tempfile
import uuid

import aiohttp
import docker

from tom.store import Store
from tom.proxy import resolve_public


async def run(root, repo, client):
    namespace = "tom-it-" + uuid.uuid4().hex[:6]
    app_name = namespace + "-app"
    port_socket = socket.socket()
    port_socket.bind(("127.0.0.1", 0))
    port = port_socket.getsockname()[1]
    port_socket.close()
    origin = f"http://127.0.0.1:{port}"
    raw = dict(
        data_dir=str(root / "data"),
        public_origin=origin,
        access_team="team",
        access_aud="aud",
        users=["owner@example.com"],
        admin_email="owner@example.com",
        namespace=namespace,
        auth_mode="local",
        local_token="tom-integration-only",
        apparmor_profile="",
        seccomp_path=str(repo / "security/seccomp.json"),
    )
    (root / "config.json").write_text(json.dumps(raw))
    (root / "key").write_bytes(os.urandom(32))
    (root / "admin.token").write_text("tom-integration-admin-only")
    (root / "run").mkdir()
    store = Store(root / "data", (root / "key").read_bytes())
    instance = store.create_instance("owner@example.com", "Integration assistant")
    occupied = set()
    for n in client.networks.list():
        for p in n.attrs.get("IPAM", {}).get("Config") or []:
            subnet = p.get("Subnet", "")
            if subnet.startswith("172.30."):
                occupied.add(int(subnet.split(".")[2]))
    chosen = next(n for n in range(128, 251) if n not in occupied)
    with store.db:
        store.db.execute("UPDATE instances SET subnet=? WHERE id=?", (chosen, instance["id"]))
    store.set_secret(instance["id"], "model/openai", "tom-integration-fake-model-key")
    store.close()
    env = {
        "TOM_CONFIG": str(root / "config.json"),
        "TOM_VAULT_KEY": str(root / "key"),
        "TOM_ADMIN_TOKEN_FILE": str(root / "admin.token"),
        "TOM_ALLOW_LOCAL_AUTH": "1",
        "TOM_RUNTIME_DIR": str(root / "run"),
        "TOM_APP_CONTAINER": app_name,
        "TOM_REQUIREMENTS_PATH": str(repo / "security/requirements.toml"),
        "TOM_INTEGRATION_DIAGNOSTICS": "1",
    }
    app = client.containers.run(
        "tom-app:0.1.0",
        name=app_name,
        detach=True,
        environment=env,
        volumes={
            str(root): {"bind": str(root), "mode": "rw"},
            str(repo / "security"): {"bind": str(repo / "security"), "mode": "ro"},
            "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"},
        },
        ports={"8080/tcp": ("127.0.0.1", port)},
        labels={"tom.test": namespace},
        mem_limit="512m",
    )
    async with aiohttp.ClientSession(
        headers={"Authorization": "Bearer tom-integration-only"},
        timeout=aiohttp.ClientTimeout(total=120),
    ) as session:

        async def api(path, body=None):
            async with session.request(
                "GET" if body is None else "POST", origin + path, json=body
            ) as r:
                data = await r.json()
                if r.status >= 400:
                    raise RuntimeError(f"{path}: HTTP {r.status}: {data}")
                return data

        for _ in range(60):
            try:
                async with session.get(
                    origin + "/healthz", timeout=aiohttp.ClientTimeout(total=2)
                ) as response:
                    if response.status == 200:
                        break
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
            await asyncio.sleep(1)
        else:
            raise RuntimeError("Management container failed to start")
        base = "/api/instances/" + instance["id"]
        print("Management container healthy", flush=True)
        await api(base + "/start", {})
        print("Gateway and sandboxed browser healthy", flush=True)
        history = await api(base + "/history")
        assert isinstance(history.get("messages"), list)
        print("Actual gateway handshake and history RPC passed", flush=True)
        await api(base + "/approvals")
        print("Actual approvals RPC passed", flush=True)
        control = await api(base + "/take-control", {})
        gateway = client.containers.get(f"{namespace}-{instance['id'][:12]}-gateway")
        browser = client.containers.get(f"{namespace}-{instance['id'][:12]}-browser")
        gateway.reload()
        browser.reload()
        assert gateway.status == "paused" and browser.status == "running"
        print("Takeover freezes the gateway and preserves the browser", flush=True)
        tabs = await api(base + "/tabs")
        assert tabs
        target = tabs[0]["id"]
        async with session.ws_connect(
            origin + base + "/stream?target=" + target, headers={"Origin": origin}
        ) as ws:
            frame = await asyncio.wait_for(ws.receive_json(), 15)
            assert frame["type"] == "frame" and len(frame["data"]) > 100
            await ws.send_json({"type": "click", "x": 20, "y": 20, "token": control["token"]})
        print("Real browser streaming and input passed", flush=True)
        try:
            await resolve_public("example.com")
            public_dns = True
        except (ValueError, OSError):
            public_dns = False
        async with session.post(
            origin + base + "/browser",
            json={"type": "navigate", "target": target, "url": "https://example.com"},
            headers={"X-Tom-Control": control["token"]},
        ) as r:
            assert r.status == (200 if public_dns else 400), await r.text()
        print(
            "HTTPS browsing passed"
            if public_dns
            else "Reserved test DNS correctly blocked; live internet browsing requires public DNS",
            flush=True,
        )
        async with session.post(
            origin + base + "/release-control", json={}, headers={"X-Tom-Control": control["token"]}
        ) as r:
            assert r.status == 200, await r.text()
        gateway.reload()
        assert gateway.status == "running"
        # Write a memory note through the actual guest's persistent workspace.
        result = gateway.exec_run(
            [
                "node",
                "-e",
                "require('fs').writeFileSync('/home/node/.openclaw/workspace/MEMORY.md','# Memory\\nPersistent integration note\\n')",
            ]
        )
        assert result.exit_code == 0
        assert "Persistent integration note" in (await api(base + "/memory"))["text"]
        await api(base + "/stop", {})
        await api(base + "/start", {})
        assert "Persistent integration note" in (await api(base + "/memory"))["text"]
        print("Stop/restart preserves memory and separates container state", flush=True)
        link = await api(base + "/console-launch", {})
        assert link["url"].startswith(origin + "/instances/" + instance["id"] + "/console/#")
        async with session.get(origin + "/instances/" + instance["id"] + "/console/") as r:
            assert r.status == 200
            assert "openclaw" in (await r.text()).lower()
        print("Scoped upstream OpenClaw interface and pairing link passed", flush=True)
        await api(base + "/stop", {})
    app.remove(force=True)
    print("Docker integration checks passed; no real model request was sent", flush=True)


def main():
    repo = Path(__file__).resolve().parent.parent
    client = docker.from_env()
    with tempfile.TemporaryDirectory(prefix="tom-integration-") as directory:
        root = Path(directory)
        try:
            asyncio.run(run(root, repo, client))
        except Exception:
            for c in client.containers.list(all=True):
                if any(
                    m.get("Source", "") == str(root)
                    or m.get("Source", "").startswith(str(root) + "/")
                    for m in c.attrs.get("Mounts", [])
                ):
                    print(c.name, c.status, c.logs(tail=30).decode(errors="replace"), flush=True)
            raise
        finally:
            # Only fixtures created with this temporary data mount are eligible for cleanup.
            ids = set()
            for c in client.containers.list(all=True):
                if any(
                    m.get("Source", "") == str(root)
                    or m.get("Source", "").startswith(str(root) + "/")
                    for m in c.attrs.get("Mounts", [])
                ):
                    ids.update(
                        x for x in [c.labels.get("tom.namespace"), c.labels.get("tom.test")] if x
                    )
                    c.remove(force=True)
            for n in client.networks.list():
                if (
                    n.attrs.get("Labels", {}).get("tom.namespace")
                    and n.attrs.get("Labels", {}).get("tom.namespace") in ids
                ):
                    n.remove()
            # The fixtures were written by container UID 0/1000. Restore their owner before
            # TemporaryDirectory removes them; this utility mounts only this unique test directory.
            client.containers.run(
                "tom-app:0.1.0",
                [
                    "python",
                    "-c",
                    "import os,sys;uid=int(sys.argv[1]);gid=int(sys.argv[2]);"
                    "[(os.chown(os.path.join(p,n),uid,gid,follow_symlinks=False)) "
                    "for p,ds,fs in os.walk('/cleanup') for n in ds+fs];os.chown('/cleanup',uid,gid)",
                    str(os.getuid()),
                    str(os.getgid()),
                ],
                entrypoint=[],
                network_mode="none",
                remove=True,
                user="0:0",
                volumes={str(root): {"bind": "/cleanup", "mode": "rw"}},
                cap_drop=["ALL"],
                cap_add=["CHOWN", "FOWNER", "DAC_OVERRIDE"],
                security_opt=["no-new-privileges:true"],
                mem_limit="64m",
            )
    client.close()


if __name__ == "__main__":
    main()
