"""Idempotent Cloudflare setup. No DNS record is published before Access is configured."""

import base64
import json
import secrets
import urllib.request
import urllib.error
from pathlib import Path


class Cloudflare:
    def __init__(self, token, account, zone):
        self.token, self.account, self.zone = token, account, zone

    def request(self, method, path, data=None):
        req = urllib.request.Request(
            "https://api.cloudflare.com/client/v4" + path,
            method=method,
            data=json.dumps(data).encode() if data is not None else None,
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError(
                f"Cloudflare refused {method} {path} (HTTP {error.code}); check token permissions"
            ) from None
        if not result.get("success"):
            codes = [str(e.get("code", "unknown")) for e in result.get("errors", [])]
            raise RuntimeError("Cloudflare request failed (codes " + ", ".join(codes) + ")")
        return result.get("result")

    def bootstrap(self, hostname, emails, state_path: Path):
        state = json.loads(state_path.read_text()) if state_path.exists() else {}
        if state and (
            state["hostname"] != hostname
            or state["account"] != self.account
            or state["zone"] != self.zone
        ):
            raise ValueError(
                "Existing Cloudflare state belongs to a different hostname/account/zone"
            )
        state.update(hostname=hostname, account=self.account, zone=self.zone)

        def save():
            state_path.write_text(json.dumps(state, indent=2) + "\n")
            state_path.chmod(0o600)

        zone = self.request("GET", f"/zones/{self.zone}")
        if hostname != zone["name"] and not hostname.endswith("." + zone["name"]):
            raise ValueError("Hostname does not belong to the selected DNS zone")
        organization = self.request("GET", f"/accounts/{self.account}/access/organizations")
        team = organization.get("auth_domain", "").removesuffix(".cloudflareaccess.com")
        if not team:
            raise RuntimeError("Create a Cloudflare Zero Trust organization before running setup")
        root = f"/accounts/{self.account}"
        name = "Tom · " + hostname

        if "app_id" not in state:
            apps = self.request("GET", root + "/access/apps")
            if any(a.get("domain") == hostname for a in apps):
                raise RuntimeError(
                    "An Access app already protects this hostname; refusing to replace it"
                )
            app = self.request(
                "POST",
                root + "/access/apps",
                {"name": name, "domain": hostname, "type": "self_hosted", "session_duration": "8h"},
            )
            state["app_id"] = app["id"]
            save()
        app = self.request("GET", root + "/access/apps/" + state["app_id"])
        if app.get("domain") != hostname or app.get("name") != name:
            raise RuntimeError("Access app identity changed; refusing to modify it")
        policy = {
            "name": "Invited Tom users",
            "decision": "allow",
            "include": [{"email": {"email": e}} for e in emails],
            "require": [],
            "exclude": [],
        }
        policies_path = root + "/access/apps/" + state["app_id"] + "/policies"
        if "policy_id" in state:
            self.request("PUT", policies_path + "/" + state["policy_id"], policy)
        else:
            state["policy_id"] = self.request("POST", policies_path, policy)["id"]
            save()
        if "tunnel_id" not in state:
            tunnel = self.request(
                "POST",
                root + "/cfd_tunnel",
                {
                    "name": "tom-" + hostname.replace(".", "-"),
                    "config_src": "cloudflare",
                    "tunnel_secret": base64.b64encode(secrets.token_bytes(32)).decode(),
                },
            )
            state["tunnel_id"] = tunnel["id"]
            save()
        self.request(
            "PUT",
            root + "/cfd_tunnel/" + state["tunnel_id"] + "/configurations",
            {
                "config": {
                    "ingress": [
                        {"hostname": hostname, "service": "http://tom-app:8080"},
                        {"service": "http_status:404"},
                    ]
                }
            },
        )
        tunnel_token = self.request("GET", root + "/cfd_tunnel/" + state["tunnel_id"] + "/token")
        records_path = f"/zones/{self.zone}/dns_records"
        record = {
            "type": "CNAME",
            "name": hostname,
            "content": state["tunnel_id"] + ".cfargotunnel.com",
            "proxied": True,
            "ttl": 1,
        }
        if "dns_id" in state:
            previous = self.request("GET", records_path + "/" + state["dns_id"])
            if previous.get("name") != hostname:
                raise RuntimeError("DNS record identity changed; refusing to modify it")
            self.request("PUT", records_path + "/" + state["dns_id"], record)
        else:
            existing = self.request("GET", records_path + "?name=" + hostname)
            if existing:
                raise RuntimeError("DNS record already exists; refusing to overwrite it")
            state["dns_id"] = self.request("POST", records_path, record)["id"]
            save()
        state.update(status="configured", team=team, aud=app["aud"])
        self.verify_resources(state, emails)
        save()
        return team, app["aud"], tunnel_token

    def verify_resources(self, state, emails):
        root = f"/accounts/{self.account}"
        app = self.request("GET", root + "/access/apps/" + state["app_id"])
        policies = self.request("GET", root + "/access/apps/" + state["app_id"] + "/policies")
        policy = next((p for p in policies if p.get("id") == state["policy_id"]), None)
        if app.get("domain") != state["hostname"] or app.get("aud") != state["aud"]:
            raise RuntimeError("Cloudflare Access app readback did not match this installation")
        if not policy or policy.get("decision") != "allow":
            raise RuntimeError("Invited-user Access policy was not installed")
        actual = sorted(
            p.get("email", {}).get("email", "").lower() for p in policy.get("include", [])
        )
        if actual != sorted(emails) or any(p.get("decision") == "bypass" for p in policies):
            raise RuntimeError(
                "Access policy readback differs from the invited users or includes a bypass"
            )
        tunnel = self.request("GET", root + "/cfd_tunnel/" + state["tunnel_id"] + "/configurations")
        routes = tunnel.get("config", {}).get("ingress", [])
        if not any(
            r.get("hostname") == state["hostname"] and r.get("service") == "http://tom-app:8080"
            for r in routes
        ):
            raise RuntimeError("Cloudflare tunnel ingress did not match the Tom app")
        dns = self.request("GET", f"/zones/{self.zone}/dns_records/" + state["dns_id"])
        if (
            dns.get("name") != state["hostname"]
            or dns.get("type") != "CNAME"
            or dns.get("content") != state["tunnel_id"] + ".cfargotunnel.com"
            or not dns.get("proxied")
        ):
            raise RuntimeError("Cloudflare DNS readback did not point to this proxied tunnel")
