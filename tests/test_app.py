from dataclasses import replace
import time
from unittest.mock import AsyncMock
import uuid

from aiohttp import web

from tom.app import create_app
from tom.auth import Identity
from tom.runtime import gateway_config


class FixedAuth:
    def __init__(self, email, admin=False):
        self.identity = Identity(email, admin)

    async def identify(self, request):
        return self.identity

    def check_origin(self, request):
        if request.headers.get("Origin") != "http://127.0.0.1:8080":
            raise web.HTTPForbidden(text="Wrong origin")


async def make_client(aiohttp_client, config, store, identity=None):
    runtime = AsyncMock()
    app = create_app(config, store, runtime, identity or FixedAuth("owner@example.com", True))
    return await aiohttp_client(app), runtime


async def test_cross_user_cannot_list_read_control_or_change_instance(
    aiohttp_client, config, store
):
    instance = store.create_instance("owner@example.com", "Owner")
    client, runtime = await make_client(
        aiohttp_client, config, store, FixedAuth("other@example.com")
    )
    assert await (await client.get("/api/instances")).json() == []
    for suffix in ["memory", "history", "jobs", "tabs", "browser-status"]:
        assert (await client.get(f"/api/instances/{instance['id']}/{suffix}")).status == 404
    for suffix in ["start", "stop", "take-control", "credentials", "browser"]:
        assert (
            await client.post(
                f"/api/instances/{instance['id']}/{suffix}",
                json={},
                headers={"Origin": config.public_origin},
            )
        ).status == 404
    runtime.start.assert_not_called()


async def test_spoofed_email_header_is_not_auth(aiohttp_client, config, store):
    config = replace(config, auth_mode="cloudflare", public_origin="https://tom.example.com")
    client = await aiohttp_client(create_app(config, store, AsyncMock()))
    response = await client.get(
        "/api/me", headers={"Cf-Access-Authenticated-User-Email": "owner@example.com"}
    )
    assert response.status == 401


async def test_mutation_requires_same_origin(aiohttp_client, config, store):
    client, _ = await make_client(aiohttp_client, config, store)
    response = await client.post(
        "/api/instances", json={"name": "Assistant", "owner": "owner@example.com"}
    )
    assert response.status == 403


async def test_create_queue_and_idempotent_submission(aiohttp_client, config, store):
    client, _ = await make_client(aiohttp_client, config, store)
    response = await client.post(
        "/api/instances",
        json={"name": "Research", "owner": "owner@example.com"},
        headers={"Origin": config.public_origin},
    )
    assert response.status == 201
    instance = await response.json()
    body = {"id": str(uuid.uuid4()), "message": "Read a page"}
    url = f"/api/instances/{instance['id']}/jobs"
    for _ in range(2):
        assert (
            await client.post(url, json=body, headers={"Origin": config.public_origin})
        ).status == 202
    assert len(store.jobs(instance["id"])) == 1
    response = await client.post(
        url, json={**body, "message": "Different"}, headers={"Origin": config.public_origin}
    )
    assert response.status == 400


async def test_browser_control_needs_capability(aiohttp_client, config, store):
    i = store.create_instance("owner@example.com", "Owner")
    store.update(
        i["id"], state="human", control_owner="owner@example.com", control_until=time.time() + 60
    )
    store.set_secret(i["id"], "internal/control-token", "valid-control")
    client, runtime = await make_client(aiohttp_client, config, store)
    response = await client.post(
        f"/api/instances/{i['id']}/release-control",
        json={},
        headers={"Origin": config.public_origin},
    )
    assert response.status == 403
    runtime.release_control.assert_not_called()


async def test_credential_saved_without_echo(aiohttp_client, config, store):
    i = store.create_instance("owner@example.com", "Owner")
    client, _ = await make_client(aiohttp_client, config, store)
    response = await client.post(
        f"/api/instances/{i['id']}/credentials",
        json={
            "kind": "website",
            "host": "example.com",
            "username": "my-user",
            "password": "private-value",
        },
        headers={"Origin": config.public_origin},
    )
    assert response.status == 200
    assert "private-value" not in await response.text()
    assert "private-value" not in await (await client.get("/api/instances")).text()
    assert store.get_secret(i["id"], "site/example.com")["password"] == "private-value"


async def test_memory_intermediate_symlink_cannot_read_other_instance(
    aiohttp_client, config, store
):
    own = store.create_instance("owner@example.com", "Owner")
    other = store.create_instance("other@example.com", "Other")
    target = config.data_dir / "instances" / other["id"] / "state/workspace"
    target.mkdir(parents=True)
    (target / "MEMORY.md").write_text("other-user-private-memory")
    parent = config.data_dir / "instances" / own["id"] / "state"
    parent.mkdir(parents=True)
    (parent / "workspace").symlink_to(target, target_is_directory=True)
    client, _ = await make_client(aiohttp_client, config, store, FixedAuth("owner@example.com"))
    response = await client.get(f"/api/instances/{own['id']}/memory")
    assert response.status >= 400
    assert "other-user-private-memory" not in await response.text()


def test_restart_does_not_replay_unknown_work(store):
    i = store.create_instance("owner@example.com", "Owner")
    j = store.enqueue(i["id"], "Buy something", str(uuid.uuid4()))
    store.finish_job(j["id"], "running")
    store.recover_jobs()
    assert store.job(j["id"])["state"] == "interrupted"
    assert not store.queued()


def test_generated_gateway_keeps_native_codex_and_guardian(config, store):
    i = store.create_instance("owner@example.com", "Owner")
    g = gateway_config(config, i, "browser.example")
    assert g["models"]["providers"]["openai"]["baseUrl"] == "https://api.openai.com/v1"
    assert g["models"]["providers"]["openai"]["apiKey"]["source"] == "exec"
    assert g["plugins"]["entries"]["codex"]["config"]["appServer"]["mode"] == "guardian"
    assert g["cron"]["enabled"] is False
    assert g["agents"]["defaults"]["heartbeat"]["every"] == "0m"
