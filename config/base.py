from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings with environment variable integration.

    Attributes
    ----------
    access_token_expiry: int
        Access token lifetime in minutes.
    algorithm: str
        JWT signing algorithm.
    cache_timeout_seconds: int | None, default=1800
        Default cache entry timeout in seconds.
    debug: bool
        Enable/disable debug mode.
    expires_delta: int
        Token expiration delta in minutes.
    logging_level: str
        Logging verbosity: e.g., "INFO", "DEBUG".
    refresh_token_expiry: int
        Refresh token lifetime in days.
    secret_key: str
        Key for JWT signing/verification and password-hashing.
    base_dir: Path, default=auto-detected
        Project base directory.
    environment: str, default="development"
        Application environment: "development", "production", etc.
    google_client_id: str, default=""
        Google OAuth client ID.
    google_client_secret: str, default=""
        Google OAuth client secret.
    google_redirect_uri: str, default=""
        Google OAuth redirect URI.
    google_token_url: str, default=""
        Google OAuth token exchange endpoint.
    google_user_info_url: str, default=""
        Google OAuth user info endpoint.
    min_password_length: int, default=8
        Minimum password length for users.
    logs_dir: Path, derived from base_dir
        Directory for log files.
    log_file: Path, derived from base_dir
        Main log file path.
    private_key_password: str | None, optional
        Password for RSA private key encryption.
    private_key_path: Path | None, optional
        Path to the RSA private key for JWT signing.
    public_key_path: Path | None, optional
        Path to the RSA public key for JWT verification.
    redis_host: str, default="localhost"
        Redis server hostname.
    redis_port: int, default=6379
        Redis server port.
    redis_db: int, default=0
        Redis database index.
    redis_password: str | None, optional
        Redis password.
    redis_socket_connect_timeout: int, default=5
        Redis socket connect timeout in seconds.
    redis_socket_timeout: int, default=5
        Redis socket read/write timeout in seconds.
    redis_use_ssl: bool, default=False
        Use SSL for Redis connection.
    ssl_cert_reqs: str | None, optional
        SSL certificate requirements for Redis.
    ssl_certfile_path: Path | None, optional
        Path to SSL certificate for Uvicorn.
    ssl_keyfile_path: Path | None, optional
        Path to SSL key for Uvicorn.

    Raises
    ------
    ValueError
        If required configuration values are missing or invalid.

    Notes
    -----
    Paths are resolved relative to the project root.
    Sensitive configuration values like secret keys, passwords, and private keys
    should always be provided via environment variables or secure secret management
    systems, never committed to version control or hardcoded in source files.
    """

    access_token_expiry: int
    algorithm: str
    cache_timeout_seconds: int | None = 1800
    debug: bool
    expires_delta: int
    logging_level: str
    refresh_token_expiry: int
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
    ssl_cert_reqs: str | None = None
    ssl_certfile_path: Path | None = None
    ssl_keyfile_path: Path | None = None

    model_config = SettingsConfigDict(env_file=".env", extra="allow")

    def __post_init__(self):
        """Perform post-initialization validation and directory creation.

        Ensures all file and directory paths for logging and SSL certificates exist,
        and validates algorithm-specific configuration requirements.

        Raises
        ------
        ValueError
            If secret key is missing for HS256 algorithm.
            If RSA keys or password are missing for RS256 algorithm.
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
    """Create and cache singleton Settings instance for application use.

    Returns
    -------
    Settings
        Cached singleton instance of application settings with all
        configuration values loaded and validated.
    """
    return Settings()
