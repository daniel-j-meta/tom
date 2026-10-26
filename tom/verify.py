"""Live deployment checks run by setup on the target Ubuntu server."""

import asyncio
import time
import uuid
from urllib.parse import urlsplit

import aiohttp


def is_access_challenge(status, location, origin, issuer):
    if status not in {301, 302, 303, 307, 308}:
        return False
    parsed = urlsplit(location)
    return (
        parsed.scheme == "https"
        and parsed.hostname in {urlsplit(origin).hostname, urlsplit(issuer).hostname}
        and parsed.path.startswith("/cdn-cgi/access/")
    )


async def check_public_access(origin, issuer, timeout=120):
    deadline = time.monotonic() + timeout
    last = "DNS/TLS connection unavailable"
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
        while time.monotonic() < deadline:
            try:
                async with session.get(origin + "/api/me", allow_redirects=False) as response:
                    if is_access_challenge(
                        response.status, response.headers.get("Location", ""), origin, issuer
                    ):
                        return
                    if response.status == 200:
                        raise RuntimeError(
                            "Public API allowed an anonymous request; check Cloudflare Access"
                        )
                    last = f"HTTP {response.status} without the expected Cloudflare Access login challenge"
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
            await asyncio.sleep(3)
    raise RuntimeError(
        f"Public HTTPS/Access verification failed: {last}. Check DNS, tunnel logs, and Access login settings."
    )


async def verify_deployment(
    root, config, api, wait_job, report=print, public_check=check_public_access
):
    report("Checking public HTTPS, tunnel routing, and Cloudflare Access…")
    await public_check(config.public_origin, f"https://{config.access_team}.cloudflareaccess.com")
    report("Public HTTPS and Access login challenge verified")
    rows = await api(root, "/api/instances")
    if any(row["state"] != "stopped" for row in rows):
        raise RuntimeError(
            "Live verification requires idle assistants; existing work was not interrupted"
        )
    instance = next(
        (row for row in rows if row["owner"] == config.admin_email and row["has_model_key"]), None
    )
    if not instance:
        raise RuntimeError(
            "Create an administrator-owned assistant with an OpenAI key before verification"
        )
    iid = instance["id"]
    base = f"/api/instances/{iid}"
    started = False
    try:
        report("Checking the real browser, internet access, and control handoff…")
        await api(root, base + "/start", {})
        started = True
        tabs = await api(root, base + "/tabs")
        if not tabs:
            raise RuntimeError("The browser started without an accessible tab")
        target = tabs[0]["id"]
        lease = await api(root, base + "/take-control", {})
        # The local admin API accepts headers separately; the lease stays out of URLs/logs.
        await api(
            root,
            base + "/browser",
            {"type": "navigate", "target": target, "url": "https://example.com"},
            headers={"X-Tom-Control": lease["token"]},
        )
        for _ in range(15):
            page = await api(root, base + "/browser-status?target=" + target)
            if page.get("readyState") == "complete" and "Example Domain" in page.get("text", ""):
                break
            await asyncio.sleep(1)
        else:
            raise RuntimeError("The remote browser could not load the HTTPS internet test page")
        await api(root, base + "/release-control", {}, headers={"X-Tom-Control": lease["token"]})
        report("Remote browser HTTPS access and take/give-back control verified")
        report(f"Checking {config.model} with one small live request (uses API credits)…")
        job = await api(
            root,
            base + "/jobs",
            {
                "id": str(uuid.uuid4()),
                "message": "Setup verification: reply exactly TOM_SETUP_READY. Do not use tools or perform any other action.",
            },
        )
        await wait_job(root, iid, job["id"])
        history = await api(root, base + "/history")
        messages = history.get("messages", [])
        assistant = next((m for m in reversed(messages) if m.get("role") == "assistant"), {})
        content = assistant.get("content", "")
        text = (
            content
            if isinstance(content, str)
            else "\n".join(part.get("text", "") for part in content if part.get("type") == "text")
        )
        if "TOM_SETUP_READY" not in text:
            raise RuntimeError(
                "Model request finished without the expected setup reply; inspect its conversation"
            )
        report("Live model reply verified")
    finally:
        if started:
            await api(root, base + "/stop", {})
    report("Live deployment verification passed; assistant returned to stopped state")
