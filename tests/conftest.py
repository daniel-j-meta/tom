import os
from pathlib import Path

import pytest

from tom.config import Config
from tom.store import Store


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("TOM_ALLOW_LOCAL_AUTH", "1")
    c = Config(
        tmp_path / "data",
        "http://127.0.0.1:8080",
        "team",
        "aud",
        ["owner@example.com", "other@example.com"],
        "owner@example.com",
        auth_mode="local",
        local_token="test-local-token",
        seccomp_path=str(Path(__file__).parent.parent / "security/seccomp.json"),
    )
    c.validate()
    return c


@pytest.fixture
def store(config):
    s = Store(config.data_dir, os.urandom(32))
    yield s
    s.close()
