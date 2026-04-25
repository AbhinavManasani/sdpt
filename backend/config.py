"""
Software Provenance Tracker — Application Configuration

Loads all settings from .env file using Pydantic BaseSettings.
Hard errors on startup if any required value is missing.
No mock data fallbacks — every required field must be provided.
"""

from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from functools import lru_cache


class Settings(BaseSettings):
    """
    Centralized configuration loaded from .env file.
    All fields without defaults are REQUIRED — the application
    will refuse to start if they are missing or set to placeholder values.
    """

    # ─── GitHub API ──────────────────────────────────────────
    github_token: str = Field(
        default="",
        description="GitHub Personal Access Token (classic) with repo and read:org scopes",
    )

    # ─── Auth ────────────────────────────────────────────────
    default_api_key: str = Field(
        default="sdpt-dev-key-2024",
        description="Default API key seeded into Redis on startup",
    )

    # ─── Groq (LLM) ──────────────────────────────────────────
    groq_api_key: str = Field(
        default="",
        description="Groq API key for AI-powered alert explanations",
    )

    # ─── Package Registry APIs ───────────────────────────────
    pypi_api_url: str = Field(
        default="https://pypi.org/pypi",
        description="PyPI JSON API base URL",
    )
    npm_registry_url: str = Field(
        default="https://registry.npmjs.org",
        description="npm Registry API base URL",
    )

    # ─── PostgreSQL ──────────────────────────────────────────
    postgres_host: str = Field(default="localhost")
    postgres_port: int = Field(default=5432)
    postgres_db: str = Field(default="provenance_db")
    postgres_user: str = Field(default="provenance")
    postgres_password: str = Field(
        ...,
        description="PostgreSQL password — must match docker-compose.yml",
    )

    # ─── Neo4j ───────────────────────────────────────────────
    neo4j_host: str = Field(default="localhost")
    neo4j_bolt_port: int = Field(default=7687)
    neo4j_http_port: int = Field(default=7474)
    neo4j_user: str = Field(default="neo4j")
    neo4j_password: str = Field(
        ...,
        description="Neo4j password — must match docker-compose.yml",
    )

    # ─── Redis ───────────────────────────────────────────────
    redis_host: str = Field(default="localhost")
    redis_port: int = Field(default=6379)
    redis_password: str = Field(
        ...,
        description="Redis password — must match docker-compose.yml",
    )

    # ─── Application ─────────────────────────────────────────
    app_host: str = Field(default="0.0.0.0")
    app_port: int = Field(default=8000)
    app_env: str = Field(default="development")
    app_log_level: str = Field(default="INFO")

    # ─── Dependency Resolution ───────────────────────────────
    max_dependency_depth: int = Field(
        default=10,
        ge=1,
        le=15,
        description="Max depth for transitive dependency resolution",
    )
    registry_cache_ttl: int = Field(
        default=3600,
        description="Cache TTL for registry API responses (seconds)",
    )

    # ─── GitHub Rate Limiting ────────────────────────────────
    github_cache_ttl: int = Field(
        default=1800,
        description="Cache TTL for GitHub API responses (seconds)",
    )

    # ─── Notifications ───────────────────────────────────────
    frontend_base_url: str = Field(
        default="http://localhost:5173",
        description="Frontend base URL for notification links",
    )
    slack_webhook_url: str = Field(default="", description="Slack webhook URL")
    smtp_host: str = Field(default="smtp.gmail.com", description="SMTP host")
    smtp_port: int = Field(default=587, description="SMTP port")
    smtp_user: str = Field(default="", description="SMTP username")
    smtp_password: str = Field(default="", description="SMTP password")
    alert_email_to: str = Field(default="", description="Alert recipient email")

    # ─── Validators ──────────────────────────────────────────────────────────────
    @field_validator("github_token")
    @classmethod
    def github_token_not_placeholder(cls, v: str) -> str:
        if v == "your_github_pat_here":
            raise ValueError(
                "GITHUB_TOKEN contains a placeholder value. "
                "Set a real token or remove the variable to run without auth."
            )
        return v

    @field_validator("postgres_password")
    @classmethod
    def postgres_password_not_placeholder(cls, v: str) -> str:
        if v == "your_postgres_password_here" or not v.strip():
            raise ValueError(
                "POSTGRES_PASSWORD is required. Set a real password in .env "
                "and ensure it matches docker-compose.yml."
            )
        return v

    @field_validator("neo4j_password")
    @classmethod
    def neo4j_password_not_placeholder(cls, v: str) -> str:
        if v == "your_neo4j_password_here" or not v.strip():
            raise ValueError(
                "NEO4J_PASSWORD is required. Set a real password in .env "
                "and ensure it matches docker-compose.yml."
            )
        return v

    @field_validator("redis_password")
    @classmethod
    def redis_password_not_placeholder(cls, v: str) -> str:
        if v == "your_redis_password_here" or not v.strip():
            raise ValueError(
                "REDIS_PASSWORD is required. Set a real password in .env "
                "and ensure it matches docker-compose.yml."
            )
        return v

    # ─── Computed Properties ─────────────────────────────────
    @property
    def postgres_dsn(self) -> str:
        """Full PostgreSQL connection string for SQLAlchemy."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password.replace(chr(64), chr(37)+chr(52)+chr(48))}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}?ssl=disable"
        )

    @property
    def postgres_dsn_sync(self) -> str:
        """Synchronous PostgreSQL DSN for migrations and scripts."""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}?ssl=disable"
        )

    @property
    def neo4j_uri(self) -> str:
        """Neo4j Bolt protocol URI."""
        return f"bolt://{self.neo4j_host}:{self.neo4j_bolt_port}"

    @property
    def redis_url(self) -> str:
        """Redis connection URL."""
        return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/0"

    model_config = {
        "env_file": ["/mnt/c/Users/lenovo/Documents/Software Provenance Tracker/.env", ".env"],
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


@lru_cache()
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.
    Raises ValidationError on startup if any required
    field is missing or contains a placeholder value.
    """
    return Settings()
