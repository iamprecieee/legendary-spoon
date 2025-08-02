from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file.

    Attributes:
        access_token_expiry: Expiry time for access tokens in minutes.
        algorithm: Algorithm used for JWT signing.
        cache_timeout_seconds: Default timeout for cache entries in seconds (default: 1800).
        debug: Boolean indicating if debug mode is enabled.
        expires_delta: Delta for token expiration in minutes.
        logging_level: Logging level for the application (e.g., "INFO", "DEBUG").
        refresh_token_expiry: Expiry time for refresh tokens in days.
        secret_key: Secret key for signing JWTs and other cryptographic operations.
        base_dir: Base directory of the project (auto-detected).
        environment: Application environment (e.g., "development", "production").
        google_client_id: Google OAuth client ID.
        google_client_secret: Google OAuth client secret.
        google_redirect_uri: Google OAuth redirect URI.
        google_token_url: Google OAuth token exchange URL.
        google_user_info_url: Google OAuth user information URL.
        min_password_length: Minimum required length for user passwords (default: 8).
        logs_dir: Directory for storing log files (derived from base_dir).
        log_file: Path to the main log file (derived from logs_dir).
        redis_host: Redis server host.
        redis_port: Redis server port.
        redis_db: Redis database number.
        redis_password: Redis server password (optional).
        redis_socket_connect_timeout: Socket connection timeout for Redis.
        redis_socket_timeout: Socket read/write timeout for Redis.
        redis_use_ssl: Boolean indicating if Redis SSL should be used.
        ssl_certfile_path: Path to the SSL certificate file for Uvicorn (optional).
        ssl_keyfile_path: Path to the SSL key file for Uvicorn (optional).
    """

    access_token_expiry: int  # minutes
    algorithm: str
    cache_timeout_seconds: int | None = 1800
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
    google_token_url: str = ""
    google_user_info_url: str = ""
    min_password_length: int = 8
    logs_dir: Path = base_dir / "logs"
    log_file: Path = logs_dir / "phantom.log"
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str | None = None
    redis_socket_connect_timeout: int = 5
    redis_socket_timeout: int = 5
    redis_use_ssl: bool = False
    ssl_cert_reqs: str | None = None
    ssl_certfile_path: Path | None = None
    ssl_keyfile_path: Path | None = None

    model_config = SettingsConfigDict(env_file=".env", extra="allow")

    def __post_init__(self):
        """Post-initialization hook to ensure necessary directories and files exist.

        Creates the logs directory and touches the log and SSL files to ensure their presence.
        """
        self.logs_dir.mkdir(exist_ok=True)
        self.log_file.touch(exist_ok=True)
        if self.ssl_certfile_path:
            self.ssl_certfile_path.touch(exist_ok=True)
        if self.ssl_keyfile_path:
            self.ssl_keyfile_path.touch(exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Provides a cached instance of application settings.

    Uses `lru_cache` to ensure settings are loaded only once.

    Returns:
        A singleton instance of `Settings`.
    """
    return Settings()
