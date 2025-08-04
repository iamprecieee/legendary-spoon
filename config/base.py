from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file.

    Attributes:
        access_token_expiry (int): Access token lifetime in minutes.
        algorithm (str): JWT signing algorithm.
        cache_timeout_seconds (int | None): Default cache entry timeout in seconds (default: 1800).
        debug (bool): Enable/disable debug mode.
        expires_delta (int): Token expiration delta in minutes.
        logging_level (str): Logging verbosity (e.g., "INFO", "DEBUG").
        refresh_token_expiry (int): Refresh token lifetime in days.
        base_dir (Path): Project base directory (auto-detected).
        environment (str): Application environment ("development", "production", etc.).
        google_client_id (str): Google OAuth client ID.
        google_client_secret (str): Google OAuth client secret.
        google_redirect_uri (str): Google OAuth redirect URI.
        google_token_url (str): Google OAuth token exchange endpoint.
        google_user_info_url (str): Google OAuth user info endpoint.
        min_password_length (int): Minimum password length for users (default: 8).
        logs_dir (Path): Directory for log files (derived from base_dir).
        log_file (Path): Main log file path (derived from logs_dir).
        private_key_password (str | None): Password for RSA private key encryption (optional).
        private_key_path (Path | None): Path to the RSA private key for JWT signing (optional).
        public_key_path (Path | None): Path to the RSA public key for JWT verification (optional).
        redis_host (str): Redis server hostname.
        redis_port (int): Redis server port.
        redis_db (int): Redis database index.
        redis_password (str | None): Redis password (optional).
        redis_socket_connect_timeout (int): Redis socket connect timeout (seconds).
        redis_socket_timeout (int): Redis socket read/write timeout (seconds).
        redis_use_ssl (bool): Use SSL for Redis connection.
        secret_key (str | None): Key for JWT signing/verification (optional).
        ssl_cert_reqs (str | None): SSL certificate requirements for Redis (optional).
        ssl_certfile_path (Path | None): Path to SSL certificate for Uvicorn (optional).
        ssl_keyfile_path (Path | None): Path to SSL key for Uvicorn (optional).

    Notes:
        - All settings can be configured via environment variables or a `.env` file.
        - Paths are resolved relative to the project root.
        - Directories and files for logging and SSL are created/touched if missing.
    """

    access_token_expiry: int  # minutes
    algorithm: str
    cache_timeout_seconds: int | None = 1800
    debug: bool
    expires_delta: int  # minutes
    logging_level: str
    refresh_token_expiry: int  # days
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
    private_key_password: str | None = None
    private_key_path: Path | None = None
    public_key_path: Path | None = None
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str | None = None
    redis_socket_connect_timeout: int = 5
    redis_socket_timeout: int = 5
    redis_use_ssl: bool = False
    secret_key: str | None = None  # Only used if algorithm is HS256
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

        if self.algorithm == "HS256" and self.secret_key is None:
            raise ValueError("Secret Key value is required for this algorithm")
        elif self.algorithm == "RS256" and any(
            [
                self.private_key_path is None,
                self.public_key_path is None,
                self.private_key_password is None,
            ]
        ):
            raise ValueError(
                "RSA public/private keys and password are required for this algorithm"
            )


@lru_cache
def get_settings() -> Settings:
    """
    Return a cached singleton instance of application settings.

    Uses `lru_cache` to ensure settings are loaded only once.

    Returns:
        Settings: The singleton application settings instance.
    """
    return Settings()
