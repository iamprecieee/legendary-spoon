from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    secret_key: str
    algorithm: str
    expires_delta: int
    access_token_expiry: int
    refresh_token_expiry: int
    logging_level: str
    environment: str = "development"
    base_dir: Path = Path(__file__).resolve().parent.parent
    logs_dir: Path = base_dir / "logs"
    log_file: Path = logs_dir / "phantom.log"

    model_config = SettingsConfigDict(env_file=".env")

    def __post_init__(self):
        self.logs_dir.mkdir(exist_ok=True)
        self.log_file.touch(exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Returns a cached instance of Settings."""

    return Settings()
