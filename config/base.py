from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    access_token_expiry: int  # minutes
    algorithm: str
    debug: bool
    expires_delta: int  # minutes
    logging_level: str
    refresh_token_expiry: int  # days
    secret_key: str
    base_dir: Path = Path(__file__).resolve().parent.parent
    environment: str = "development"
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = ""
    min_password_length: int = 8
    logs_dir: Path = base_dir / "logs"
    log_file: Path = logs_dir / "phantom.log"
    ssl_certfile_path: str | None = None
    ssl_keyfile_path: str | None = None

    model_config = SettingsConfigDict(env_file=".env", extra="allow")

    def __post_init__(self):
        self.logs_dir.mkdir(exist_ok=True)
        self.log_file.touch(exist_ok=True)
        self.ssl_certfile.touch(exist_ok=True)
        self.ssl_keyfile.touch(exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Returns a cached instance of Settings."""

    return Settings()
