"""Tests for Prometheus client module."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
import respx
from httpx import Response

from prometheus_mcp_server.client import PrometheusClient
from prometheus_mcp_server.config import Settings
from prometheus_mcp_server.exceptions import (
    PrometheusAPIError,
    PrometheusConnectionError,
    PrometheusQueryError,
    PrometheusTimeoutError,
)


class TestPrometheusClient:
    """Test PrometheusClient class."""

    @pytest.mark.asyncio
    async def test_connect_disconnect(self, settings: Settings):
        """Test client connection lifecycle."""
        client = PrometheusClient(settings=settings)

        assert client._client is None
        await client.connect()
        assert client._client is not None
        await client.close()
        assert client._client is None

    @pytest.mark.asyncio
    async def test_context_manager(self, settings: Settings):
        """Test async context manager."""
        async with PrometheusClient(settings=settings) as client:
            assert client._client is not None
        assert client._client is None

    @pytest.mark.asyncio
    async def test_query(
        self,
        settings: Settings,
        mock_prometheus,
        mock_query_response: dict,
    ):
        """Test instant query."""
        mock_prometheus.post("/api/v1/query").mock(
            return_value=Response(200, json=mock_query_response)
        )

        async with PrometheusClient(settings=settings) as client:
            result = await client.query("up")

        assert result["resultType"] == "vector"
        assert len(result["result"]) == 2

    @pytest.mark.asyncio
    async def test_query_with_time(
        self,
        settings: Settings,
        mock_prometheus,
        mock_query_response: dict,
    ):
        """Test instant query with time parameter."""
        mock_prometheus.post("/api/v1/query").mock(
            return_value=Response(200, json=mock_query_response)
        )

        async with PrometheusClient(settings=settings) as client:
            result = await client.query("up", time="5m")

        assert result["resultType"] == "vector"

    @pytest.mark.asyncio
    async def test_query_range(
        self,
        settings: Settings,
        mock_prometheus,
        mock_range_query_response: dict,
    ):
        """Test range query."""
        mock_prometheus.post("/api/v1/query_range").mock(
            return_value=Response(200, json=mock_range_query_response)
        )

        async with PrometheusClient(settings=settings) as client:
            result = await client.query_range(
                "up",
                start="1h",
                end="now",
                step="1m",
            )

        assert result["resultType"] == "matrix"
        assert len(result["result"]) == 1
        assert len(result["result"][0]["values"]) == 3

    @pytest.mark.asyncio
    async def test_get_alerts(
        self,
        settings: Settings,
        mock_prometheus,
        mock_alerts_response: dict,
    ):
        """Test getting alerts."""
        mock_prometheus.get("/api/v1/alerts").mock(
            return_value=Response(200, json=mock_alerts_response)
        )

        async with PrometheusClient(settings=settings) as client:
            alerts = await client.get_alerts()

        assert len(alerts) == 2
        assert alerts[0]["labels"]["alertname"] == "HighMemory"
        assert alerts[0]["state"] == "firing"
        assert alerts[1]["state"] == "pending"

    @pytest.mark.asyncio
    async def test_get_targets(
        self,
        settings: Settings,
        mock_prometheus,
        mock_targets_response: dict,
    ):
        """Test getting targets."""
        mock_prometheus.get("/api/v1/targets").mock(
            return_value=Response(200, json=mock_targets_response)
        )

        async with PrometheusClient(settings=settings) as client:
            targets = await client.get_targets()

        assert len(targets["activeTargets"]) == 2
        assert targets["activeTargets"][0]["health"] == "up"
        assert targets["activeTargets"][1]["health"] == "down"

    @pytest.mark.asyncio
    async def test_get_rules(
        self,
        settings: Settings,
        mock_prometheus,
        mock_rules_response: dict,
    ):
        """Test getting rules."""
        mock_prometheus.get("/api/v1/rules").mock(
            return_value=Response(200, json=mock_rules_response)
        )

        async with PrometheusClient(settings=settings) as client:
            rules = await client.get_rules()

        assert len(rules["groups"]) == 1
        assert len(rules["groups"][0]["rules"]) == 2

    @pytest.mark.asyncio
    async def test_get_labels(
        self,
        settings: Settings,
        mock_prometheus,
        mock_labels_response: dict,
    ):
        """Test getting label names."""
        mock_prometheus.get("/api/v1/labels").mock(
            return_value=Response(200, json=mock_labels_response)
        )

        async with PrometheusClient(settings=settings) as client:
            labels = await client.get_labels()

        assert "__name__" in labels
        assert "job" in labels

    @pytest.mark.asyncio
    async def test_get_label_values(
        self,
        settings: Settings,
        mock_prometheus,
        mock_label_values_response: dict,
    ):
        """Test getting label values."""
        mock_prometheus.get("/api/v1/label/job/values").mock(
            return_value=Response(200, json=mock_label_values_response)
        )

        async with PrometheusClient(settings=settings) as client:
            values = await client.get_label_values("job")

        assert "prometheus" in values
        assert "node" in values

    @pytest.mark.asyncio
    async def test_get_series(
        self,
        settings: Settings,
        mock_prometheus,
        mock_series_response: dict,
    ):
        """Test getting series."""
        mock_prometheus.post("/api/v1/series").mock(
            return_value=Response(200, json=mock_series_response)
        )

        async with PrometheusClient(settings=settings) as client:
            series = await client.get_series(match=["up"])

        assert len(series) == 2

    @pytest.mark.asyncio
    async def test_get_metadata(
        self,
        settings: Settings,
        mock_prometheus,
        mock_metadata_response: dict,
    ):
        """Test getting metric metadata."""
        mock_prometheus.get("/api/v1/metadata").mock(
            return_value=Response(200, json=mock_metadata_response)
        )

        async with PrometheusClient(settings=settings) as client:
            metadata = await client.get_metric_metadata()

        assert "up" in metadata
        assert metadata["up"][0]["type"] == "gauge"

    @pytest.mark.asyncio
    async def test_get_build_info(
        self,
        settings: Settings,
        mock_prometheus,
        mock_build_info_response: dict,
    ):
        """Test getting build info."""
        mock_prometheus.get("/api/v1/status/buildinfo").mock(
            return_value=Response(200, json=mock_build_info_response)
        )

        async with PrometheusClient(settings=settings) as client:
            info = await client.get_build_info()

        assert info["version"] == "2.48.0"

    @pytest.mark.asyncio
    async def test_health_check(
        self,
        settings: Settings,
        mock_prometheus,
    ):
        """Test health check."""
        mock_prometheus.get("/-/healthy").mock(return_value=Response(200, text="OK"))

        async with PrometheusClient(settings=settings) as client:
            healthy = await client.is_healthy()

        assert healthy is True

    @pytest.mark.asyncio
    async def test_health_check_unhealthy(
        self,
        settings: Settings,
        mock_prometheus,
    ):
        """Test health check when unhealthy."""
        mock_prometheus.get("/-/healthy").mock(return_value=Response(503))

        async with PrometheusClient(settings=settings) as client:
            healthy = await client.is_healthy()

        assert healthy is False

    @pytest.mark.asyncio
    async def test_ready_check(
        self,
        settings: Settings,
        mock_prometheus,
    ):
        """Test readiness check."""
        mock_prometheus.get("/-/ready").mock(return_value=Response(200, text="OK"))

        async with PrometheusClient(settings=settings) as client:
            ready = await client.is_ready()

        assert ready is True


class TestTimeParser:
    """Test time parsing functionality."""

    @pytest.mark.asyncio
    async def test_parse_relative_time_seconds(self, settings: Settings):
        """Test parsing relative time in seconds."""
        client = PrometheusClient(settings=settings)

        result = client._parse_time("30s")
        expected = datetime.now() - timedelta(seconds=30)

        # Allow 1 second tolerance
        assert abs(float(result) - expected.timestamp()) < 1

    @pytest.mark.asyncio
    async def test_parse_relative_time_minutes(self, settings: Settings):
        """Test parsing relative time in minutes."""
        client = PrometheusClient(settings=settings)

        result = client._parse_time("5m")
        expected = datetime.now() - timedelta(minutes=5)

        assert abs(float(result) - expected.timestamp()) < 1

    @pytest.mark.asyncio
    async def test_parse_relative_time_hours(self, settings: Settings):
        """Test parsing relative time in hours."""
        client = PrometheusClient(settings=settings)

        result = client._parse_time("1h")
        expected = datetime.now() - timedelta(hours=1)

        assert abs(float(result) - expected.timestamp()) < 1

    @pytest.mark.asyncio
    async def test_parse_relative_time_days(self, settings: Settings):
        """Test parsing relative time in days."""
        client = PrometheusClient(settings=settings)

        result = client._parse_time("7d")
        expected = datetime.now() - timedelta(days=7)

        assert abs(float(result) - expected.timestamp()) < 1

    @pytest.mark.asyncio
    async def test_parse_now(self, settings: Settings):
        """Test parsing 'now'."""
        client = PrometheusClient(settings=settings)

        result = client._parse_time("now")
        expected = datetime.now()

        assert abs(float(result) - expected.timestamp()) < 1

    @pytest.mark.asyncio
    async def test_parse_unix_timestamp(self, settings: Settings):
        """Test parsing Unix timestamp."""
        client = PrometheusClient(settings=settings)

        result = client._parse_time("1704067200")
        assert result == "1704067200"

    @pytest.mark.asyncio
    async def test_parse_datetime_object(self, settings: Settings):
        """Test parsing datetime object."""
        client = PrometheusClient(settings=settings)
        dt = datetime(2024, 1, 1, 0, 0, 0)

        result = client._parse_time(dt)
        assert result == str(dt.timestamp())

    @pytest.mark.asyncio
    async def test_parse_none(self, settings: Settings):
        """Test parsing None."""
        client = PrometheusClient(settings=settings)

        result = client._parse_time(None)
        assert result is None


class TestErrorHandling:
    """Test error handling."""

    @pytest.mark.asyncio
    async def test_query_error(
        self,
        settings: Settings,
        mock_prometheus,
    ):
        """Test handling of PromQL query errors."""
        error_response = {
            "status": "error",
            "errorType": "bad_data",
            "error": "invalid PromQL expression",
        }
        mock_prometheus.post("/api/v1/query").mock(
            return_value=Response(200, json=error_response)
        )

        async with PrometheusClient(settings=settings) as client:
            with pytest.raises(PrometheusQueryError) as exc_info:
                await client.query("invalid{")

        assert "bad_data" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_http_400_error(
        self,
        settings: Settings,
        mock_prometheus,
    ):
        """Test handling of HTTP 400 errors."""
        mock_prometheus.post("/api/v1/query").mock(
            return_value=Response(400, text="Bad Request")
        )

        async with PrometheusClient(settings=settings) as client:
            with pytest.raises(PrometheusQueryError):
                await client.query("test")

    @pytest.mark.asyncio
    async def test_http_401_error(
        self,
        settings: Settings,
        mock_prometheus,
    ):
        """Test handling of HTTP 401 errors."""
        mock_prometheus.post("/api/v1/query").mock(
            return_value=Response(401, text="Unauthorized")
        )

        async with PrometheusClient(settings=settings) as client:
            with pytest.raises(PrometheusAPIError) as exc_info:
                await client.query("test")

        assert "Authentication failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_http_403_error(
        self,
        settings: Settings,
        mock_prometheus,
    ):
        """Test handling of HTTP 403 errors."""
        mock_prometheus.post("/api/v1/query").mock(
            return_value=Response(403, text="Forbidden")
        )

        async with PrometheusClient(settings=settings) as client:
            with pytest.raises(PrometheusAPIError) as exc_info:
                await client.query("test")

        assert "Access denied" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_http_503_error(
        self,
        settings: Settings,
        mock_prometheus,
    ):
        """Test handling of HTTP 503 errors."""
        mock_prometheus.post("/api/v1/query").mock(
            return_value=Response(503, text="Service Unavailable")
        )

        async with PrometheusClient(settings=settings) as client:
            with pytest.raises(PrometheusAPIError) as exc_info:
                await client.query("test")

        assert "Service unavailable" in str(exc_info.value)
