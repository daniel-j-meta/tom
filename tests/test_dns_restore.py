import json
import tarfile
from unittest.mock import Mock

from dnslib import DNSRecord, RCODE
import pytest

from tom.cli import restore_tar
from tom.dns import GuestDNS


async def test_dns_only_own_services_and_public_addresses(store):
    instance = store.create_instance("owner@example.com", "Owner")
    store.update(instance["id"], state="running")
    runtime = Mock()
    runtime.addresses.return_value = {"gateway": "172.30.1.3", "browser": "172.30.1.4"}
    runtime.name.side_effect = lambda iid, role: "my-" + role
    dns = GuestDNS(store, runtime)
    dns.transport = Mock()
    await dns.answer(DNSRecord.question("my-browser").pack(), ("172.30.1.3", 9999))
    response = DNSRecord.parse(dns.transport.sendto.call_args.args[0])
    assert str(response.rr[0].rdata) == "172.30.1.4"
    await dns.answer(DNSRecord.question("127.0.0.1").pack(), ("172.30.1.3", 9999))
    assert DNSRecord.parse(dns.transport.sendto.call_args.args[0]).header.rcode == RCODE.NXDOMAIN
    await dns.answer(DNSRecord.question("my-browser").pack(), ("172.30.9.3", 9999))
    assert DNSRecord.parse(dns.transport.sendto.call_args.args[0]).header.rcode == RCODE.REFUSED


def archive_fixture(tmp_path, malicious=False):
    source = tmp_path / "source"
    source.mkdir()
    (source / "data").mkdir()
    (source / "secrets").mkdir()
    (source / "secrets/vault.key").write_bytes(b"x" * 32)
    (source / "config.json").write_text(
        json.dumps({"data_dir": "/old/data", "seccomp_path": "/old/security/seccomp.json"})
    )
    if malicious:
        (source / "data/escape").symlink_to("/etc")
    archive = tmp_path / "backup.tar.gz"
    with tarfile.open(archive, "w:gz") as out:
        for name in ["data", "secrets", "config.json"]:
            out.add(source / name, arcname=name)
    return archive


def test_restore_empty_target_and_rewrite_paths(tmp_path):
    archive = archive_fixture(tmp_path)
    target = tmp_path / "restored"
    target.mkdir()
    restore_tar(target, archive)
    assert json.loads((target / "config.json").read_text())["data_dir"] == str(target / "data")
    assert (target / "secrets/vault.key").read_bytes() == b"x" * 32
    with pytest.raises(ValueError):
        restore_tar(target, archive)


def test_restore_rejects_escape_without_partial_commit(tmp_path):
    archive = archive_fixture(tmp_path, malicious=True)
    target = tmp_path / "restored"
    target.mkdir()
    with pytest.raises((ValueError, tarfile.FilterError)):
        restore_tar(target, archive)
    assert not (target / "data").exists()
    assert not (target / "secrets").exists()
