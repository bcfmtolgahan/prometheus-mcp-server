"""Pytest configuration and fixtures."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from prometheus_mcp_server.config import Settings, clear_settings_cache
from prometheus_mcp_server.client import PrometheusClient


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear settings cache before each test."""
    clear_settings_cache()
    yield
    clear_settings_cache()


@pytest.fixture
def settings() -> Settings:
    """Create test settings."""
    return Settings(
        url="http://localhost:9090",
        timeout=5.0,
        max_retries=1,
    )


@pytest.fixture
def settings_with_basic_auth() -> Settings:
    """Create test settings with basic auth."""
    return Settings(
        url="http://localhost:9090",
        auth_type="basic",
        auth_username="admin",
        auth_password="secret",
        timeout=5.0,
        max_retries=1,
    )


@pytest.fixture
def settings_with_bearer_auth() -> Settings:
    """Create test settings with bearer auth."""
    return Settings(
        url="http://localhost:9090",
        auth_type="bearer",
        auth_token="test-token",
        timeout=5.0,
        max_retries=1,
    )


@pytest.fixture
async def client(settings: Settings) -> PrometheusClient:
    """Create a test client."""
    client = PrometheusClient(settings=settings)
    await client.connect()
    yield client
    await client.close()


@pytest.fixture
def mock_prometheus():
    """Mock Prometheus API responses."""
    with respx.mock(base_url="http://localhost:9090") as mock:
        yield mock


# =============================================================================
# Common Mock Responses
# =============================================================================


@pytest.fixture
def mock_query_response() -> dict:
    """Mock instant query response."""
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {
                    "metric": {"__name__": "up", "job": "prometheus", "instance": "localhost:9090"},
                    "value": [1704067200, "1"],
                },
                {
                    "metric": {"__name__": "up", "job": "node", "instance": "localhost:9100"},
                    "value": [1704067200, "1"],
                },
            ],
        },
    }


@pytest.fixture
def mock_range_query_response() -> dict:
    """Mock range query response."""
    return {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {"__name__": "up", "job": "prometheus"},
                    "values": [
                        [1704067200, "1"],
                        [1704067260, "1"],
                        [1704067320, "1"],
                    ],
                },
            ],
        },
    }


@pytest.fixture
def mock_alerts_response() -> dict:
    """Mock alerts response."""
    return {
        "status": "success",
        "data": {
            "alerts": [
                {
                    "labels": {
                        "alertname": "HighMemory",
                        "severity": "warning",
                        "instance": "localhost:9100",
                    },
                    "annotations": {
                        "summary": "High memory usage",
                        "description": "Memory usage is above 80%",
                    },
                    "state": "firing",
                    "activeAt": "2024-01-01T00:00:00Z",
                    "value": "85",
                },
                {
                    "labels": {
                        "alertname": "HighCPU",
                        "severity": "critical",
                        "instance": "localhost:9100",
                    },
                    "annotations": {
                        "summary": "High CPU usage",
                    },
                    "state": "pending",
                    "activeAt": "2024-01-01T01:00:00Z",
                    "value": "95",
                },
            ],
        },
    }


@pytest.fixture
def mock_targets_response() -> dict:
    """Mock targets response."""
    return {
        "status": "success",
        "data": {
            "activeTargets": [
                {
                    "discoveredLabels": {"__address__": "localhost:9090"},
                    "labels": {"job": "prometheus", "instance": "localhost:9090"},
                    "scrapePool": "prometheus",
                    "scrapeUrl": "http://localhost:9090/metrics",
                    "globalUrl": "http://localhost:9090/metrics",
                    "lastError": "",
                    "lastScrape": "2024-01-01T00:00:00Z",
                    "lastScrapeDuration": 0.01,
                    "health": "up",
                },
                {
                    "discoveredLabels": {"__address__": "localhost:9100"},
                    "labels": {"job": "node", "instance": "localhost:9100"},
                    "scrapePool": "node",
                    "scrapeUrl": "http://localhost:9100/metrics",
                    "globalUrl": "http://localhost:9100/metrics",
                    "lastError": "connection refused",
                    "lastScrape": "2024-01-01T00:00:00Z",
                    "lastScrapeDuration": 0.0,
                    "health": "down",
                },
            ],
            "droppedTargets": [],
        },
    }


@pytest.fixture
def mock_rules_response() -> dict:
    """Mock rules response."""
    return {
        "status": "success",
        "data": {
            "groups": [
                {
                    "name": "example",
                    "file": "/etc/prometheus/rules.yml",
                    "rules": [
                        {
                            "name": "HighMemory",
                            "type": "alerting",
                            "query": "node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes < 0.2",
                            "duration": 300,
                            "labels": {"severity": "warning"},
                            "annotations": {"summary": "High memory usage"},
                            "health": "ok",
                            "state": "inactive",
                        },
                        {
                            "name": "instance:node_cpu:rate5m",
                            "type": "recording",
                            "query": "rate(node_cpu_seconds_total[5m])",
                            "health": "ok",
                        },
                    ],
                },
            ],
        },
    }


@pytest.fixture
def mock_labels_response() -> dict:
    """Mock labels response."""
    return {
        "status": "success",
        "data": ["__name__", "instance", "job", "severity"],
    }


@pytest.fixture
def mock_label_values_response() -> dict:
    """Mock label values response."""
    return {
        "status": "success",
        "data": ["prometheus", "node", "alertmanager"],
    }


@pytest.fixture
def mock_series_response() -> dict:
    """Mock series response."""
    return {
        "status": "success",
        "data": [
            {"__name__": "up", "job": "prometheus", "instance": "localhost:9090"},
            {"__name__": "up", "job": "node", "instance": "localhost:9100"},
        ],
    }


@pytest.fixture
def mock_metadata_response() -> dict:
    """Mock metadata response."""
    return {
        "status": "success",
        "data": {
            "up": [
                {
                    "type": "gauge",
                    "help": "1 if the target is up, 0 otherwise",
                    "unit": "",
                },
            ],
            "process_cpu_seconds_total": [
                {
                    "type": "counter",
                    "help": "Total user and system CPU time spent in seconds",
                    "unit": "seconds",
                },
            ],
        },
    }


@pytest.fixture
def mock_build_info_response() -> dict:
    """Mock build info response."""
    return {
        "status": "success",
        "data": {
            "version": "2.48.0",
            "revision": "abcdef123456",
            "branch": "HEAD",
            "buildUser": "root@buildhost",
            "buildDate": "20240101-00:00:00",
            "goVersion": "go1.21.5",
        },
    }
