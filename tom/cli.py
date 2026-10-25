import argparse
import asyncio
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import tarfile
import tempfile
import shutil
from pathlib import PurePosixPath

import aiohttp

from .cloudflare import Cloudflare
from .config import Config
from .store import Store


def prompt(label, default="", hidden=False):
    value = (
        getpass.getpass(label + ": ")
        if hidden
        else input(label + (f" [{default}]" if default else "") + ": ")
    )
    return value.strip() or default


def bootstrap(root, reconfigure=False):
    root = Path(root).resolve()
    config_path = root / "config.json"
    if config_path.exists() and not reconfigure:
        config = Config.load(config_path)
        print("Existing configuration retained:", config.public_origin)
        return
    hostname = prompt("App hostname (DNS must be managed by Cloudflare)")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", hostname):
        raise ValueError("Enter a hostname without https:// or a path")
    admin = prompt("Your sign-in email").lower()
    invited = prompt("Other invited emails, comma-separated (optional)")
    emails = sorted(set([admin] + [x.strip().lower() for x in invited.split(",") if x.strip()]))
    if not all(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) for email in emails):
        raise ValueError("Enter valid email addresses")
    account = prompt("Cloudflare account ID")
    zone = prompt("Cloudflare DNS zone ID")
    if not all(re.fullmatch(r"[a-f0-9]{32}", x) for x in [account, zone]):
        raise ValueError("Cloudflare IDs must contain 32 hexadecimal characters")
    token = prompt("Cloudflare API token", hidden=True)
    model = prompt("OpenAI model ID", "gpt-6-luna")
    openai_key = prompt("OpenAI API key (stored encrypted)", hidden=True)
    if not token or not openai_key:
        raise ValueError("Both API credentials are required")
    directory = root / "secrets"
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    key_path = directory / "vault.key"
    if not key_path.exists():
        key_path.write_bytes(secrets.token_bytes(32))
        key_path.chmod(0o400)
    admin_path = directory / "admin.token"
    if not admin_path.exists():
        admin_path.write_text(secrets.token_urlsafe(48))
        admin_path.chmod(0o400)
    print("Configuring Cloudflare Access, a tunnel, and then DNS…")
    team, aud, tunnel_token = Cloudflare(token, account, zone).bootstrap(
        hostname, emails, directory / "cloudflare-state.json"
    )
    tunnel_path = directory / "tunnel.token"
    tunnel_path.write_text(tunnel_token)
    tunnel_path.chmod(0o400)
    if os.geteuid() == 0:
        os.chown(tunnel_path, 65532, 65532)
    raw = dict(
        data_dir=str(root / "data"),
        public_origin="https://" + hostname,
        access_team=team,
        access_aud=aud,
        users=emails,
        admin_email=admin,
        model=model,
        seccomp_path=str(root / "security/seccomp.json"),
    )
    temporary = config_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(raw, indent=2) + "\n")
    temporary.chmod(0o600)
    Config.load(temporary)
    temporary.replace(config_path)
    store = Store(root / "data", key_path.read_bytes())
    store.set_secret("system", "default-openai", openai_key)
    if not store.all_instances():
        for email in emails:
            instance = store.create_instance(email, email.split("@")[0] + "'s assistant")
            store.set_secret(instance["id"], "model/openai", openai_key)
    store.close()
    print("Configured", raw["public_origin"], "for", len(emails), "invited users.")


async def admin_api(root, path, body=None):
    token = (root / "secrets/admin.token").read_text().strip()
    async with aiohttp.ClientSession(
        connector=aiohttp.UnixConnector(path="/run/tom/admin.sock")
    ) as session:
        async with session.request(
            "GET" if body is None else "POST",
            "http://tom" + path,
            json=body,
            headers={"Authorization": "Bearer " + token},
        ) as response:
            data = await response.json()
            if response.status >= 400:
                raise RuntimeError(data.get("error", "Request failed"))
            return data


async def wait_job(root, iid, jid, timeout=330):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        jobs = await admin_api(root, f"/api/instances/{iid}/jobs")
        job = next((j for j in jobs if j["id"] == jid), None)
        if job and job["state"] == "complete":
            return job
        if job and job["state"] in {"failed", "interrupted"}:
            raise RuntimeError(job["result"] or "Live model check failed")
        await asyncio.sleep(2)
    raise RuntimeError("Live check did not finish; inspect the queue before retrying")


def compose(root, *args):
    env = {**os.environ, "TOM_ROOT": str(root)}
    return subprocess.run(
        [
            "docker",
            "compose",
            "--project-directory",
            str(root),
            "-f",
            str(root / "compose.yaml"),
            *args,
        ],
        env=env,
        check=True,
    )


def restore_tar(root, decrypted):
    names = ["data", "secrets", "config.json"]
    if any(
        (root / n).exists() and (not (root / n).is_dir() or any((root / n).iterdir()))
        for n in names
    ):
        raise ValueError(
            "Restore requires empty data/secrets directories and no existing configuration"
        )
    with tempfile.TemporaryDirectory(prefix="tom-restore-stage-", dir=root) as temporary:
        stage = Path(temporary)
        with tarfile.open(decrypted) as archive:

            def guarded(member, destination):
                parts = PurePosixPath(member.name).parts
                if (
                    not parts
                    or parts[0] not in names
                    or ".." in parts
                    or member.name.startswith("/")
                ):
                    raise ValueError("Archive contains an unsupported path")
                safe = tarfile.data_filter(member, destination)
                if safe is None:
                    return None
                if len(parts) >= 3 and parts[:2] == ("data", "instances"):
                    boundary = (stage / "data/instances" / parts[2]).resolve()
                    if not (stage / member.name).resolve().is_relative_to(boundary):
                        raise ValueError("Archive crosses instance boundaries")
                    if member.issym() or member.islnk():
                        target = (
                            ((stage / member.name).parent / member.linkname)
                            if member.issym()
                            else (stage / member.linkname)
                        )
                        if not target.resolve().is_relative_to(boundary):
                            raise ValueError("Archive link crosses instance boundaries")
                elif member.issym() or member.islnk():
                    raise ValueError("Links outside an instance are not supported")
                if (
                    os.geteuid() == 0
                    and member.uid in {0, 1000, 65532}
                    and member.gid in {0, 1000, 65532}
                ):
                    safe = safe.replace(uid=member.uid, gid=member.gid)
                return safe

            archive.extractall(stage, filter=guarded)
        if not (stage / "config.json").is_file() or not (stage / "secrets/vault.key").is_file():
            raise ValueError("Archive is missing its configuration or vault recovery key")
        raw = json.loads((stage / "config.json").read_text())
        raw["data_dir"] = str(root / "data")
        raw["seccomp_path"] = str(root / "security/seccomp.json")
        (stage / "config.json").write_text(json.dumps(raw, indent=2) + "\n")
        for name in names:
            destination = root / name
            if destination.is_dir():
                destination.rmdir()
            shutil.move(str(stage / name), destination)


def main():
    parser = argparse.ArgumentParser(description="Manage the Tom home server")
    parser.add_argument("--root", default=os.getenv("TOM_ROOT", "/opt/tom"))
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("configure")
    setup.add_argument("--reconfigure", action="store_true")
    sub.add_parser("status")
    for command in ["start", "stop", "logs"]:
        p = sub.add_parser(command)
        p.add_argument("instance", nargs="?" if command == "logs" else None)
    doctor = sub.add_parser("doctor")
    doctor.add_argument(
        "--live", action="store_true", help="Send a tiny model request; uses API credits"
    )
    sub.add_parser("up")
    sub.add_parser("down")
    backup = sub.add_parser("backup")
    backup.add_argument(
        "--recipient", required=True, help="age public key; keep its private key offline"
    )
    backup.add_argument("--output", required=True)
    restore = sub.add_parser("restore")
    restore.add_argument("--identity", required=True)
    restore.add_argument("--archive", required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    try:
        if args.command == "configure":
            bootstrap(root, args.reconfigure)
        elif args.command == "status":
            for i in asyncio.run(admin_api(root, "/api/instances")):
                print(i["id"], i["state"].ljust(9), i["owner"], i["name"])
        elif args.command in {"start", "stop"}:
            print(
                asyncio.run(admin_api(root, f"/api/instances/{args.instance}/{args.command}", {}))
            )
        elif args.command == "logs":
            if args.instance:
                if not re.fullmatch(r"[a-f0-9]{32}", args.instance):
                    raise ValueError("Use the full instance ID from tom status")
                subprocess.run(
                    ["docker", "logs", "--tail", "80", f"tom-{args.instance[:12]}-gateway"],
                    check=True,
                )
            else:
                compose(root, "logs", "--tail", "80", "app", "cloudflared")
        elif args.command == "up":
            compose(root, "up", "-d", "--wait", "--wait-timeout", "120")
        elif args.command == "down":
            for i in asyncio.run(admin_api(root, "/api/instances")):
                asyncio.run(admin_api(root, f"/api/instances/{i['id']}/stop", {}))
            compose(root, "down")
        elif args.command == "doctor":
            config = Config.load(root / "config.json")
            rows = asyncio.run(admin_api(root, "/api/instances"))
            print("Management API authenticated;", len(rows), "saved assistants.")
            print("Cloudflare origin:", config.public_origin)
            print("Active limit:", config.max_active, "· model:", config.model)
            if args.live:
                if not rows:
                    raise ValueError("Create an assistant first")
                job = asyncio.run(
                    admin_api(
                        root,
                        f"/api/instances/{rows[0]['id']}/jobs",
                        {
                            "id": str(__import__("uuid").uuid4()),
                            "message": "Reply with READY only.",
                        },
                    )
                )
                print("Live model check queued:", job["id"], "— inspect its result in the app.")
                asyncio.run(wait_job(root, rows[0]["id"], job["id"]))
                print("Live model request completed successfully")
        elif args.command == "backup":
            output = Path(args.output).resolve()
            if output.exists():
                raise ValueError("Backup output already exists; refusing to replace it")
            asyncio.run(admin_api(root, "/api/admin/maintenance", {"enabled": True}))
            # Stop browser and gateway writes, then stop the management database writer.
            for i in asyncio.run(admin_api(root, "/api/instances")):
                asyncio.run(admin_api(root, f"/api/instances/{i['id']}/stop", {}))
            compose(root, "stop", "app")
            try:
                tar = subprocess.Popen(
                    ["tar", "-C", str(root), "-czf", "-", "data", "secrets", "config.json"],
                    stdout=subprocess.PIPE,
                )
                result = subprocess.run(
                    ["age", "-r", args.recipient, "-o", str(output)], stdin=tar.stdout
                )
                tar.stdout.close()
                tar_status = tar.wait()
                if result.returncode or tar_status:
                    output.unlink(missing_ok=True)
                    raise RuntimeError("Encrypted backup failed")
            finally:
                compose(root, "start", "app")
            output.chmod(0o600)
            print("Encrypted backup saved:", output)
        elif args.command == "restore":
            if (root / "data/tom.sqlite").exists():
                raise ValueError(
                    "Restore requires an empty installation; existing data is never overwritten"
                )
            root.mkdir(parents=True, exist_ok=True)
            # Stream into a private staging directory and validate paths before extraction.

            with tempfile.TemporaryDirectory(prefix="tom-restore-") as staging:
                decrypted = Path(staging) / "backup.tar.gz"
                with decrypted.open("wb") as out:
                    subprocess.run(
                        ["age", "-d", "-i", args.identity, args.archive], stdout=out, check=True
                    )
                restore_tar(root, decrypted)
            print(
                "Restored. Run setup.sh to rebuild services without changing retained configuration."
            )
    except (
        ValueError,
        RuntimeError,
        OSError,
        subprocess.CalledProcessError,
        aiohttp.ClientError,
    ) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
