from dataclasses import dataclass, field
from pathlib import Path
import json
import re
import os


@dataclass
class Config:
    data_dir: Path
    public_origin: str
    access_team: str
    access_aud: str
    users: list[str]
    admin_email: str
    image: str = "tom-openclaw:2026.10.7"
    max_active: int = 1
    max_instances: int = 10
    gateway_memory_mb: int = 2048
    browser_memory_mb: int = 1536
    idle_seconds: int = 180
    control_seconds: int = 900
    model: str = "gpt-6-luna"
    namespace: str = "tom"
    network_pool: str = "172.30.0.0/16"
    apparmor_profile: str = "tom-guest"
    seccomp_path: str = "/opt/tom/security/seccomp.json"
    auth_mode: str = "cloudflare"
    local_token: str = field(default="", repr=False)

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        raw = json.loads(Path(path).read_text())
        raw["data_dir"] = Path(raw["data_dir"])
        config = cls(**raw)
        config.validate()
        return config

    def validate(self):
        if not self.data_dir.is_absolute():
            raise ValueError("data_dir must be absolute")
        if not 1 <= self.max_active <= 2 or not 1 <= self.max_instances <= 20:
            raise ValueError("Use 1–2 active instances and at most 20 saved instances")
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,20}", self.namespace):
            raise ValueError("Invalid container namespace")
        if self.network_pool != "172.30.0.0/16":
            raise ValueError("This release reserves 172.30.0.0/16 for isolated instances")
        if not re.fullmatch(r"[a-zA-Z0-9._-]+", self.model):
            raise ValueError("Invalid model ID")
        self.users = sorted(set(x.strip().lower() for x in self.users))
        self.admin_email = self.admin_email.strip().lower()
        if self.admin_email not in self.users:
            raise ValueError("Administrator must be an invited user")
        if self.auth_mode == "cloudflare":
            if not re.fullmatch(r"[a-z0-9-]+", self.access_team) or not self.access_aud:
                raise ValueError(
                    "Cloudflare team name and Access application audience are required"
                )
            if not re.fullmatch(r"https://[a-z0-9.-]+", self.public_origin):
                raise ValueError("public_origin must be an HTTPS hostname without a path")
        elif self.auth_mode == "local":
            if not self.local_token or os.getenv("TOM_ALLOW_LOCAL_AUTH") != "1":
                raise ValueError("Local authentication requires an explicit development opt-in")
        else:
            raise ValueError("Unsupported authentication mode")
