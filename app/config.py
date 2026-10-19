"""Runtime settings for the AgentGate Claims API.

Everything that changes between environments (keys, secrets, URLs) comes from
environment variables. Nothing secret is ever hard-coded or committed.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Tiny .env loader so local dev works without extra packages.

    Real environment variables always win over values in the file.
    """
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(ROOT / ".env")


class Settings:
    issuer: str = os.environ.get("AGENTGATE_ISSUER", "https://auth.agentgate.example")
    audience: str = os.environ.get("AGENTGATE_AUDIENCE", "agentgate-claims-api")
    token_ttl_seconds: int = int(os.environ.get("AGENTGATE_TOKEN_TTL_SECONDS", "900"))
    private_key_pem: str | None = os.environ.get("AGENTGATE_PRIVATE_KEY_PEM")
    state_dir: Path = Path(os.environ.get("AGENTGATE_STATE_DIR", str(ROOT / "state")))
    rate_limit_per_minute: int = int(os.environ.get("AGENTGATE_RATE_LIMIT_PER_MINUTE", "120"))
    cors_origins: list[str] = [
        o.strip()
        for o in os.environ.get("AGENTGATE_CORS_ORIGINS", "https://claims.agentgate.example").split(",")
        if o.strip()
    ]
    clients_file: Path = ROOT / "config" / "clients.yaml"
    catalog_file: Path = ROOT / "catalog" / "agentgate-claims.yaml"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    return settings


@lru_cache
def load_catalog_entry() -> dict:
    """The API catalog entry is the single source of truth for lifecycle info
    (which versions exist, which are deprecated, when they sunset)."""
    return yaml.safe_load(get_settings().catalog_file.read_text())
