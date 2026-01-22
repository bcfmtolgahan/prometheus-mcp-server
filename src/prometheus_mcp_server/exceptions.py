"""
Custom exceptions for Prometheus MCP Server.
"""

from __future__ import annotations


class PrometheusMCPError(Exception):
    """Base exception for all Prometheus MCP Server errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} - Details: {self.details}"
        return self.message


class PrometheusConnectionError(PrometheusMCPError):
    """Raised when connection to Prometheus fails."""

    pass


class PrometheusTimeoutError(PrometheusMCPError):
    """Raised when a request to Prometheus times out."""

    pass


class PrometheusAPIError(PrometheusMCPError):
    """Raised when Prometheus API returns an error."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        error_type: str | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.status_code = status_code
        self.error_type = error_type


class PrometheusQueryError(PrometheusAPIError):
    """Raised when a PromQL query is invalid or fails."""

    pass


class PrometheusAuthError(PrometheusAPIError):
    """Raised when authentication fails."""

    pass


class ConfigurationError(PrometheusMCPError):
    """Raised when configuration is invalid."""

    pass


class ToolExecutionError(PrometheusMCPError):
    """Raised when a tool execution fails."""

    def __init__(
        self,
        message: str,
        tool_name: str,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.tool_name = tool_name
