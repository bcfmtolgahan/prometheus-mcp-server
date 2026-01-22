"""Tests for configuration module."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from prometheus_mcp_server.config import (
    AuthType,
    LogLevel,
    Settings,
    TransportType,
    clear_settings_cache,
    get_settings,
)


class TestSettings:
    """Test Settings class."""

    def test_default_settings(self):
        """Test default settings values."""
        settings = Settings()

        assert settings.url == "http://localhost:9090"
        assert settings.auth_type == AuthType.NONE
        assert settings.tls_verify is True
        assert settings.timeout == 30.0
        assert settings.max_retries == 3
        assert settings.transport == TransportType.STDIO
        assert settings.log_level == LogLevel.INFO
        assert settings.enable_dangerous_tools is False

    def test_url_validation(self):
        """Test URL validation."""
        # Valid URLs
        Settings(url="http://localhost:9090")
        Settings(url="https://prometheus.example.com")
        Settings(url="http://prometheus:9090/")  # Trailing slash is removed

        # Invalid URLs
        with pytest.raises(ValidationError):
            Settings(url="localhost:9090")  # Missing scheme

        with pytest.raises(ValidationError):
            Settings(url="ftp://prometheus:9090")  # Invalid scheme

    def test_url_normalization(self):
        """Test that trailing slash is removed from URL."""
        settings = Settings(url="http://localhost:9090/")
        assert settings.url == "http://localhost:9090"

    def test_basic_auth_validation(self):
        """Test basic auth requires username and password."""
        # Valid basic auth
        Settings(
            auth_type=AuthType.BASIC,
            auth_username="admin",
            auth_password="secret",
        )

        # Missing password
        with pytest.raises(ValidationError):
            Settings(auth_type=AuthType.BASIC, auth_username="admin")

        # Missing username
        with pytest.raises(ValidationError):
            Settings(auth_type=AuthType.BASIC, auth_password="secret")

    def test_bearer_auth_validation(self):
        """Test bearer auth requires token."""
        # Valid bearer auth
        Settings(auth_type=AuthType.BEARER, auth_token="my-token")

        # Missing token
        with pytest.raises(ValidationError):
            Settings(auth_type=AuthType.BEARER)

    def test_aws_sigv4_auth_validation(self):
        """Test AWS SigV4 auth requires region."""
        # Valid AWS auth
        Settings(auth_type=AuthType.AWS_SIGV4, aws_region="us-west-2")

        # Missing region
        with pytest.raises(ValidationError):
            Settings(auth_type=AuthType.AWS_SIGV4)

    def test_tls_config_validation(self):
        """Test TLS configuration validation."""
        # Client cert requires key
        with pytest.raises(ValidationError):
            Settings(tls_client_cert=Path("/path/to/cert.pem"))

        # Client key requires cert
        with pytest.raises(ValidationError):
            Settings(tls_client_key=Path("/path/to/key.pem"))

    def test_timeout_validation(self):
        """Test timeout range validation."""
        # Valid range
        Settings(timeout=1.0)
        Settings(timeout=300.0)

        # Too low
        with pytest.raises(ValidationError):
            Settings(timeout=0.5)

        # Too high
        with pytest.raises(ValidationError):
            Settings(timeout=400.0)

    def test_port_validation(self):
        """Test port range validation."""
        Settings(port=1)
        Settings(port=65535)

        with pytest.raises(ValidationError):
            Settings(port=0)

        with pytest.raises(ValidationError):
            Settings(port=65536)

    def test_get_auth_headers_bearer(self):
        """Test auth headers for bearer token."""
        settings = Settings(auth_type=AuthType.BEARER, auth_token="my-token")
        headers = settings.get_auth_headers()
        assert headers == {"Authorization": "Bearer my-token"}

    def test_get_auth_headers_none(self):
        """Test auth headers for no auth."""
        settings = Settings()
        headers = settings.get_auth_headers()
        assert headers == {}

    def test_get_basic_auth(self):
        """Test basic auth credentials."""
        settings = Settings(
            auth_type=AuthType.BASIC,
            auth_username="admin",
            auth_password="secret",
        )
        auth = settings.get_basic_auth()
        assert auth == ("admin", "secret")

    def test_get_basic_auth_none(self):
        """Test basic auth returns None when not configured."""
        settings = Settings()
        auth = settings.get_basic_auth()
        assert auth is None

    def test_from_environment(self, monkeypatch):
        """Test settings from environment variables."""
        monkeypatch.setenv("PROMETHEUS_MCP_URL", "http://prom:9090")
        monkeypatch.setenv("PROMETHEUS_MCP_TIMEOUT", "60")
        monkeypatch.setenv("PROMETHEUS_MCP_LOG_LEVEL", "DEBUG")

        clear_settings_cache()
        settings = get_settings()

        assert settings.url == "http://prom:9090"
        assert settings.timeout == 60.0
        assert settings.log_level == LogLevel.DEBUG


class TestGetSettings:
    """Test get_settings function."""

    def test_caching(self):
        """Test that settings are cached."""
        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2

    def test_clear_cache(self):
        """Test cache clearing."""
        settings1 = get_settings()
        clear_settings_cache()
        settings2 = get_settings()
        assert settings1 is not settings2
