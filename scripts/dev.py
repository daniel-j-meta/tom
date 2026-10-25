"""Local UI preview. Uses the real store/auth/API but does not pretend to run an agent."""

import argparse
import asyncio
import os
from pathlib import Path
import tempfile

from aiohttp import web

from tom.app import create_app
from tom.config import Config
from tom.runtime import Busy
from tom.store import Store


class PreviewRuntime:
    async def start(self, iid):
        raise Busy("UI preview only: deploy the Docker package to start an assistant")

    async def stop(self, iid):
        return


async def main(port):
    os.environ["TOM_ALLOW_LOCAL_AUTH"] = "1"
    with tempfile.TemporaryDirectory(prefix="tom-ui-preview-") as directory:
        config = Config(
            Path(directory),
            f"http://127.0.0.1:{port}",
            "team",
            "aud",
            ["owner@example.com", "tester@example.com"],
            "owner@example.com",
            auth_mode="local",
            local_token="tom-preview-only",
        )
        config.validate()
        store = Store(config.data_dir, os.urandom(32))
        app = create_app(config, store, PreviewRuntime())
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", port).start()
        print(f"UI preview: http://127.0.0.1:{port}; token: tom-preview-only", flush=True)
        try:
            await asyncio.Event().wait()
        finally:
            await runner.cleanup()
            store.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8787)
    asyncio.run(main(parser.parse_args().port))
