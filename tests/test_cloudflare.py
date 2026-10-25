import pytest

from tom.cloudflare import Cloudflare


class FakeCloudflare(Cloudflare):
    def __init__(self):
        super().__init__("not-a-real-token", "account", "zone")
        self.calls = []
        self.records = []

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        if path == "/zones/zone":
            return {"name": "example.com"}
        if path.endswith("/organizations"):
            return {"auth_domain": "team.cloudflareaccess.com"}
        if path.endswith("/access/apps") and method == "GET":
            return []
        if path.endswith("/access/apps") and method == "POST":
            return {"id": "app", "aud": "aud"}
        if path.endswith("/access/apps/app"):
            return {
                "id": "app",
                "aud": "aud",
                "name": "Tom · tom.example.com",
                "domain": "tom.example.com",
            }
        if path.endswith("/policies"):
            return {"id": "policy"}
        if path.endswith("/cfd_tunnel"):
            return {"id": "tunnel"}
        if path.endswith("/token"):
            return "tunnel-token"
        if "dns_records?" in path:
            return self.records
        if path.endswith("/dns_records"):
            self.records = [{**data, "id": "dns"}]
            return self.records[0]
        if path.endswith("/dns_records/dns") and method == "GET":
            return self.records[0]
        return {}


def test_access_before_dns_and_rerun_without_duplicate_resources(tmp_path):
    cf = FakeCloudflare()
    state = tmp_path / "state.json"
    result = cf.bootstrap("tom.example.com", ["owner@example.com"], state)
    assert result == ("team", "aud", "tunnel-token")
    policy_index = next(
        i for i, c in enumerate(cf.calls) if c[0] == "POST" and c[1].endswith("/policies")
    )
    dns_index = next(
        i for i, c in enumerate(cf.calls) if c[0] == "POST" and c[1].endswith("/dns_records")
    )
    assert policy_index < dns_index
    cf.calls.clear()
    cf.bootstrap("tom.example.com", ["owner@example.com"], state)
    assert not any(c[0] == "POST" for c in cf.calls)


def test_existing_dns_is_not_overwritten(tmp_path):
    cf = FakeCloudflare()
    cf.records = [{"name": "tom.example.com", "content": "another-server"}]
    with pytest.raises(RuntimeError, match="already exists"):
        cf.bootstrap("tom.example.com", ["owner@example.com"], tmp_path / "state.json")
    assert not any(c[0] == "PUT" and "dns_records" in c[1] for c in cf.calls)
