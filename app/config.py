from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="QUBE_", env_file=".env", extra="ignore")

    db_url: str = "sqlite:///./qube.db"
    jwt_secret: str
    master_key: str  # hex, 16 bytes

    member_token_days: int = 365
    admin_token_hours: int = 12

    # Online taps whose counter is this far below the tag's high-water mark are rejected,
    # so a stale sniffed URL can't be used live. Offline sync skips this check.
    online_counter_window: int = 50

    # Per-IP limit on /auth/join and /auth/admin-login.
    auth_rate_limit_per_minute: int = 10

    @field_validator("master_key")
    @classmethod
    def _check_master_key(cls, v: str) -> str:
        try:
            raw = bytes.fromhex(v)
        except ValueError as e:
            raise ValueError("QUBE_MASTER_KEY must be hex") from e
        if len(raw) != 16:
            raise ValueError("QUBE_MASTER_KEY must be 16 bytes (32 hex chars)")
        return v

    @property
    def master_key_bytes(self) -> bytes:
        return bytes.fromhex(self.master_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
