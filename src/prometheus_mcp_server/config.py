"""
Configuration management for Prometheus MCP Server.

Supports environment variables, .env files, and configuration files.
"""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(str, Enum):
    """Log level options."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class TransportType(str, Enum):
    """Transport type options."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


class AuthType(str, Enum):
    """Authentication type options."""

    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    AWS_SIGV4 = "aws_sigv4"


class Settings(BaseSettings):
    """
    Application settings with validation.

    Settings can be configured via:
    - Environment variables (prefixed with PROMETHEUS_MCP_)
    - .env file
    - Direct instantiation

    Example:
        ```bash
        export PROMETHEUS_MCP_URL="http://prometheus:9090"
        export PROMETHEUS_MCP_AUTH_TYPE="basic"
        export PROMETHEUS_MCP_AUTH_USERNAME="admin"
        export PROMETHEUS_MCP_AUTH_PASSWORD="secret"
        ```
    """

    model_config = SettingsConfigDict(
        env_prefix="PROMETHEUS_MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ==========================================================================
    # Prometheus Connection
    # ==========================================================================

    url: str = Field(
        default="http://localhost:9090",
        description="Prometheus server URL",
        examples=["http://prometheus:9090", "https://prometheus.example.com"],
    )

    # ==========================================================================
    # Authentication
    # ==========================================================================

    auth_type: AuthType = Field(
        default=AuthType.NONE,
        description="Authentication type for Prometheus connection",
    )

    auth_username: Optional[str] = Field(
        default=None,
        description="Username for basic authentication",
    )

    auth_password: Optional[SecretStr] = Field(
        default=None,
        description="Password for basic authentication",
    )

    auth_token: Optional[SecretStr] = Field(
        default=None,
        description="Bearer token for token-based authentication",
    )

    # AWS SigV4 authentication (for Amazon Managed Prometheus)
    aws_region: Optional[str] = Field(
        default=None,
        description="AWS region for SigV4 authentication",
    )

    aws_profile: Optional[str] = Field(
        default=None,
        description="AWS profile name for credentials",
    )

    aws_service: str = Field(
        default="aps",
        description="AWS service name for SigV4 (aps for Amazon Managed Prometheus)",
    )

    # ==========================================================================
    # TLS/SSL
    # ==========================================================================

    tls_verify: bool = Field(
        default=True,
        description="Verify TLS certificates",
    )

    tls_ca_cert: Optional[Path] = Field(
        default=None,
        description="Path to CA certificate file",
    )

    tls_client_cert: Optional[Path] = Field(
        default=None,
        description="Path to client certificate file",
    )

    tls_client_key: Optional[Path] = Field(
        default=None,
        description="Path to client key file",
    )

    # ==========================================================================
    # HTTP Client
    # ==========================================================================

    timeout: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="Request timeout in seconds",
    )

    max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum number of retry attempts",
    )

    retry_delay: float = Field(
        default=1.0,
        ge=0.1,
        le=60.0,
        description="Initial delay between retries in seconds",
    )

    retry_backoff: float = Field(
        default=2.0,
        ge=1.0,
        le=5.0,
        description="Backoff multiplier for retries",
    )

    max_connections: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum number of concurrent connections",
    )

    # ==========================================================================
    # Server
    # ==========================================================================

    transport: TransportType = Field(
        default=TransportType.STDIO,
        description="Transport type for MCP server",
    )

    host: str = Field(
        default="0.0.0.0",
        description="Host to bind HTTP server",
    )

    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Port for HTTP server (MCP standard: 8000)",
    )

    # ==========================================================================
    # Logging
    # ==========================================================================

    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging level",
    )

    log_format: str = Field(
        default="json",
        description="Log format (json or text)",
    )

    # ==========================================================================
    # Features
    # ==========================================================================

    enable_dangerous_tools: bool = Field(
        default=False,
        description="Enable tools that can modify Prometheus (delete series, etc.)",
    )

    max_query_samples: int = Field(
        default=50000,
        ge=1000,
        le=1000000,
        description="Maximum samples returned by range queries",
    )

    default_lookback: str = Field(
        default="1h",
        description="Default lookback period for queries",
    )

    default_step: str = Field(
        default="1m",
        description="Default step for range queries",
    )

    # ==========================================================================
    # Validators
    # ==========================================================================

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate and normalize Prometheus URL."""
        v = v.rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    @field_validator("tls_ca_cert", "tls_client_cert", "tls_client_key")
    @classmethod
    def validate_path_exists(cls, v: Optional[Path]) -> Optional[Path]:
        """Validate that certificate files exist."""
        if v is not None and not v.exists():
            raise ValueError(f"File not found: {v}")
        return v

    @model_validator(mode="after")
    def validate_auth_config(self) -> "Settings":
        """Validate authentication configuration."""
        if self.auth_type == AuthType.BASIC:
            if not self.auth_username or not self.auth_password:
                raise ValueError(
                    "Basic auth requires both auth_username and auth_password"
                )
        elif self.auth_type == AuthType.BEARER:
            if not self.auth_token:
                raise ValueError("Bearer auth requires auth_token")
        elif self.auth_type == AuthType.AWS_SIGV4:
            if not self.aws_region:
                raise ValueError("AWS SigV4 auth requires aws_region")
        return self

    @model_validator(mode="after")
    def validate_tls_config(self) -> "Settings":
        """Validate TLS configuration."""
        if self.tls_client_cert and not self.tls_client_key:
            raise ValueError("tls_client_cert requires tls_client_key")
        if self.tls_client_key and not self.tls_client_cert:
            raise ValueError("tls_client_key requires tls_client_cert")
        return self

    # ==========================================================================
    # Helpers
    # ==========================================================================

    def get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers."""
        headers: dict[str, str] = {}

        if self.auth_type == AuthType.BEARER and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token.get_secret_value()}"

        return headers

    def get_basic_auth(self) -> Optional[tuple[str, str]]:
        """Get basic auth credentials."""
        if (
            self.auth_type == AuthType.BASIC
            and self.auth_username
            and self.auth_password
        ):
            return (self.auth_username, self.auth_password.get_secret_value())
        return None


@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance.

    Returns:
        Settings: Application settings

    Example:
        ```python
        settings = get_settings()
        print(settings.url)
        ```
    """
    return Settings()


def clear_settings_cache() -> None:
    """Clear the settings cache. Useful for testing."""
    get_settings.cache_clear()
