"""
Prometheus MCP Server

A production-grade Model Context Protocol (MCP) server for Prometheus,
enabling AI agents to query metrics, analyze alerts, and perform SRE operations.
"""

from prometheus_mcp_server.server import create_server, PrometheusServer
from prometheus_mcp_server.config import Settings, get_settings
from prometheus_mcp_server.client import PrometheusClient

__version__ = "1.0.0"
__all__ = [
    "create_server",
    "PrometheusServer",
    "PrometheusClient",
    "Settings",
    "get_settings",
    "__version__",
]
