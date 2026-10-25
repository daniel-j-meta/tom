import asyncio
import base64
from dataclasses import replace
import json
import os
import time
from unittest.mock import Mock

import jwt
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa

from tom.auth import Auth
from tom.config import Config
from tom.proxy import EgressProxy, public_ip, resolve_public
from tom.store import Store


def test_credentials_ciphertext_and_instance_binding(store, config):
    store.set_secret("first", "site/example.com", {"password": "secret-not-on-disk"})
    store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    assert b"secret-not-on-disk" not in (config.data_dir / "tom.sqlite").read_bytes()
    assert store.get_secret("first", "site/example.com")["password"] == "secret-not-on-disk"
    store.db.execute("UPDATE secrets SET instance='second' WHERE instance='first'")
    with pytest.raises(InvalidTag):
        store.get_secret("second", "site/example.com")


def test_secret_survives_restart(tmp_path):
    key = os.urandom(32)
    s = Store(tmp_path, key)
    s.set_secret("one", "model/openai", "test-key")
    s.close()
    s = Store(tmp_path, key)
    assert s.get_secret("one", "model/openai") == "test-key"
    s.close()


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.30.1.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:192.168.1.1",
        "198.51.100.1",
    ],
)
def test_private_destinations_blocked(ip):
    assert not public_ip(ip)


@pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_destinations_allowed(ip):
    assert public_ip(ip)


async def test_dns_with_any_private_answer_rejected(monkeypatch):
    async def answer(*args, **kwargs):
        return [(2, 1, 6, "", ("1.1.1.1", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", answer)
    with pytest.raises(ValueError):
        await resolve_public("rebind.example")


async def test_proxy_rejects_missing_auth_and_private_target(store):
    proxy = EgressProxy(store)
    instance = store.create_instance("owner@example.com", "Owner")
    store.update(instance["id"], state="running")
    token = store.proxy_credentials(instance["id"])
    await proxy.start("127.0.0.1", 0)
    port = proxy.server.sockets[0].getsockname()[1]
    try:
        for auth, expected in [
            ("", b"407"),
            (
                "Proxy-Authorization: Basic "
                + base64.b64encode(f"{instance['id']}:{token}".encode()).decode()
                + "\r\n",
                b"403",
            ),
        ]:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"CONNECT 127.0.0.1:443 HTTP/1.1\r\n{auth}\r\n".encode())
            await writer.drain()
            assert expected in await reader.read(512)
            writer.close()
            await writer.wait_closed()
    finally:
        await proxy.close()


def test_cloudflare_signature_audience_expiry_and_invitation(config):
    c = replace(config, auth_mode="cloudflare", public_origin="https://tom.example.com")
    auth = Auth(c)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    auth.jwks = Mock()
    auth.jwks.get_signing_key_from_jwt.return_value.key = key.public_key()
    payload = {
        "iss": auth.issuer,
        "aud": "aud",
        "sub": "person",
        "iat": int(time.time()),
        "exp": int(time.time()) + 60,
        "email": "owner@example.com",
    }

    def token(changes=None):
        return jwt.encode({**payload, **(changes or {})}, key, algorithm="RS256")

    assert auth.verify_jwt(token()).admin
    for changes in [{"aud": "other"}, {"exp": 1}, {"iss": "https://attacker.example"}]:
        with pytest.raises(jwt.PyJWTError):
            auth.verify_jwt(token(changes))
    with pytest.raises(ValueError):
        auth.verify_jwt(token({"email": "uninvited@example.com"}))
    forged = jwt.encode(
        payload, rsa.generate_private_key(public_exponent=65537, key_size=2048), algorithm="RS256"
    )
    with pytest.raises(jwt.PyJWTError):
        auth.verify_jwt(forged)


def test_config_rejects_local_auth_without_opt_in(config, tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    raw = {**config.__dict__, "data_dir": str(config.data_dir)}
    path.write_text(json.dumps(raw))
    monkeypatch.delenv("TOM_ALLOW_LOCAL_AUTH")
    with pytest.raises(ValueError):
        Config.load(path)
