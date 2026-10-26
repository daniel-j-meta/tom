from unittest.mock import AsyncMock

import pytest

from tom.verify import is_access_challenge, verify_deployment


def test_public_access_must_challenge_on_the_expected_auth_host():
    origin, issuer = "https://tom.example.com", "https://team.cloudflareaccess.com"
    assert is_access_challenge(
        302, issuer + "/cdn-cgi/access/login/tom.example.com", origin, issuer
    )
    assert not is_access_challenge(200, issuer + "/cdn-cgi/access/login/", origin, issuer)
    assert not is_access_challenge(
        302, "https://attacker.example/cdn-cgi/access/login/", origin, issuer
    )


class FakeAPI:
    def __init__(self, browser_ok=True, reply="TOM_SETUP_READY", active=False):
        self.calls = []
        self.browser_ok, self.reply, self.active = browser_ok, reply, active

    async def __call__(self, root, path, body=None, headers=None):
        self.calls.append((path, body, headers))
        if path == "/api/instances":
            return [
                {
                    "id": "instance",
                    "owner": "owner@example.com",
                    "has_model_key": True,
                    "state": "running" if self.active else "stopped",
                }
            ]
        if path.endswith("/tabs"):
            return [{"id": "tab"}]
        if path.endswith("/take-control"):
            return {"token": "test-lease"}
        if path.endswith("/browser") and not self.browser_ok:
            raise RuntimeError("Proxy refused the test page")
        if "/browser-status?" in path:
            return {"readyState": "complete", "text": "Example Domain"}
        if path.endswith("/jobs"):
            return {"id": "job"}
        if path.endswith("/history"):
            return {
                "messages": [
                    {"role": "assistant", "content": [{"type": "text", "text": self.reply}]}
                ]
            }
        return {"ok": True}


async def test_live_checks_run_in_order_and_return_instance_to_idle(config):
    api, wait, public = FakeAPI(), AsyncMock(), AsyncMock()
    await verify_deployment(
        config.data_dir, config, api, wait, report=lambda _: None, public_check=public
    )
    paths = [c[0] for c in api.calls]
    assert paths.index("/api/instances/instance/browser") < paths.index(
        "/api/instances/instance/jobs"
    )
    assert paths[-1] == "/api/instances/instance/stop"
    assert next(c for c in api.calls if c[0].endswith("/browser"))[2] == {
        "X-Tom-Control": "test-lease"
    }
    public.assert_awaited_once()
    wait.assert_awaited_once()


async def test_failed_browser_check_does_not_submit_a_model_request(config):
    api = FakeAPI(browser_ok=False)
    with pytest.raises(RuntimeError, match="Proxy refused"):
        await verify_deployment(
            config.data_dir,
            config,
            api,
            AsyncMock(),
            report=lambda _: None,
            public_check=AsyncMock(),
        )
    assert api.calls[-1][0].endswith("/stop")
    assert not any(c[0].endswith("/jobs") for c in api.calls)


async def test_wrong_model_reply_fails_setup_and_cleans_up(config):
    api = FakeAPI(reply="Unexpected reply")
    with pytest.raises(RuntimeError, match="expected setup reply"):
        await verify_deployment(
            config.data_dir,
            config,
            api,
            AsyncMock(),
            report=lambda _: None,
            public_check=AsyncMock(),
        )
    assert api.calls[-1][0].endswith("/stop")


async def test_existing_user_work_is_not_interrupted(config):
    api = FakeAPI(active=True)
    with pytest.raises(RuntimeError, match="idle assistants"):
        await verify_deployment(
            config.data_dir,
            config,
            api,
            AsyncMock(),
            report=lambda _: None,
            public_check=AsyncMock(),
        )
    assert len(api.calls) == 1


async def test_failed_public_route_never_starts_an_assistant(config):
    api = FakeAPI()
    with pytest.raises(RuntimeError, match="public route"):
        await verify_deployment(
            config.data_dir,
            config,
            api,
            AsyncMock(),
            report=lambda _: None,
            public_check=AsyncMock(side_effect=RuntimeError("public route failed")),
        )
    assert not api.calls
