"""Refuse network overlaps before installing a host INPUT rule."""

import ipaddress
import json
import subprocess
import sys
from pathlib import Path

import docker

pool = ipaddress.ip_network("172.30.0.0/16")
client = docker.from_env()
occupied = []
own_bridges = set()
management = None
for network in client.networks.list():
    if (
        network.name == "tom-management"
        and (network.attrs.get("Labels") or {}).get("com.docker.compose.project") == "tom"
    ):
        entries = (network.attrs.get("IPAM") or {}).get("Config") or []
        management = next(
            (e["Subnet"] for e in entries if e.get("Subnet") and ":" not in e["Subnet"]), None
        )
    if (network.attrs.get("Labels") or {}).get("tom.namespace") == "tom":
        own_bridges.add(
            (network.attrs.get("Options") or {}).get(
                "com.docker.network.bridge.name", "br-" + network.id[:12]
            )
        )
        continue
    for entry in (network.attrs.get("IPAM") or {}).get("Config") or []:
        if entry.get("Subnet"):
            existing = ipaddress.ip_network(entry["Subnet"], strict=False)
            occupied.append(existing)
            if existing.version == 4 and existing.overlaps(pool):
                raise SystemExit(
                    "172.30.0.0/16 is already used by another Docker network. No host rule installed."
                )
routes = json.loads(subprocess.check_output(["ip", "-j", "route", "show"], text=True))
for route in routes:
    if route.get("dst", "default") == "default":
        continue
    existing = ipaddress.ip_network(route["dst"], strict=False)
    occupied.append(existing)
    if existing.version == 4 and existing.overlaps(pool):
        # Existing Tom bridges are allowed on an idempotent rerun.
        if route.get("dev", "") in own_bridges:
            continue
        raise SystemExit("Your LAN/VPN routes overlap 172.30.0.0/16. No host rule installed.")
print("Tom guest network range is available")
if not management:
    candidates = ["172.31.255.0/24", "10.242.255.0/24", "10.243.255.0/24", "192.168.249.0/24"]
    management = next(
        (
            c
            for c in candidates
            if not any(n.version == 4 and n.overlaps(ipaddress.ip_network(c)) for n in occupied)
        ),
        None,
    )
    if not management:
        raise SystemExit("No unused management subnet was found. No host rule installed.")
if len(sys.argv) > 1:
    root = Path(sys.argv[1]).resolve()
    (root / ".env").write_text(f"TOM_ROOT={root}\nTOM_MANAGEMENT_SUBNET={management}\n")
    (root / ".env").chmod(0o600)
print("Management subnet:", management)
