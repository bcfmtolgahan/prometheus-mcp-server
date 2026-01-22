"""Tests for MCP server module."""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

from prometheus_mcp_server.config import Settings
from prometheus_mcp_server.server import PrometheusServer, create_server


class TestPrometheusServer:
    """Test PrometheusServer class."""

    def test_create_server(self):
        """Test server creation."""
        server = create_server()
        assert isinstance(server, PrometheusServer)

    def test_create_server_with_settings(self):
        """Test server creation with custom settings."""
        settings = Settings(url="http://custom:9090")
        server = create_server(settings=settings)
        assert server.settings.url == "http://custom:9090"

    @pytest.mark.asyncio
    async def test_list_tools(self):
        """Test that all tools are listed."""
        server = create_server()

        # Access the list_tools handler
        tools = await server.server.list_tools()

        tool_names = [t.name for t in tools]

        # Verify core tools are present
        assert "prometheus_query" in tool_names
        assert "prometheus_query_range" in tool_names
        assert "prometheus_get_alerts" in tool_names
        assert "prometheus_get_targets" in tool_names
        assert "prometheus_get_alert_rules" in tool_names
        assert "prometheus_health_check" in tool_names

        # Dangerous tools should not be present by default
        assert "prometheus_delete_series" not in tool_names

    @pytest.mark.asyncio
    async def test_list_tools_with_dangerous_enabled(self):
        """Test that dangerous tools are listed when enabled."""
        settings = Settings(enable_dangerous_tools=True)
        server = create_server(settings=settings)

        tools = await server.server.list_tools()
        tool_names = [t.name for t in tools]

        # Dangerous tools should be present
        assert "prometheus_delete_series" in tool_names
        assert "prometheus_clean_tombstones" in tool_names
        assert "prometheus_snapshot" in tool_names


class TestToolExecution:
    """Test tool execution."""

    @pytest.fixture
    def server_with_mock(self, mock_prometheus):
        """Create server with mocked Prometheus."""
        settings = Settings(url="http://localhost:9090")
        return create_server(settings=settings)

    @pytest.mark.asyncio
    async def test_execute_query_tool(
        self,
        server_with_mock,
        mock_prometheus,
        mock_query_response,
    ):
        """Test executing prometheus_query tool."""
        mock_prometheus.post("/api/v1/query").mock(
            return_value=Response(200, json=mock_query_response)
        )
        mock_prometheus.get("/-/healthy").mock(return_value=Response(200))
        mock_prometheus.get("/-/ready").mock(return_value=Response(200))

        server = server_with_mock

        # Connect client
        from prometheus_mcp_server.client import PrometheusClient

        server.client = PrometheusClient(settings=server.settings)
        await server.client.connect()

        try:
            result = await server._execute_tool(
                "prometheus_query",
                {"query": "up"},
            )

            assert result["resultType"] == "vector"
            assert result["resultCount"] == 2
        finally:
            await server.client.close()

    @pytest.mark.asyncio
    async def test_execute_alerts_tool(
        self,
        server_with_mock,
        mock_prometheus,
        mock_alerts_response,
    ):
        """Test executing prometheus_get_alerts tool."""
        mock_prometheus.get("/api/v1/alerts").mock(
            return_value=Response(200, json=mock_alerts_response)
        )

        server = server_with_mock

        from prometheus_mcp_server.client import PrometheusClient

        server.client = PrometheusClient(settings=server.settings)
        await server.client.connect()

        try:
            result = await server._execute_tool(
                "prometheus_get_alerts",
                {},
            )

            assert result["count"] == 2
            assert "summary" in result
            assert result["summary"]["by_state"]["firing"] == 1
            assert result["summary"]["by_state"]["pending"] == 1
        finally:
            await server.client.close()

    @pytest.mark.asyncio
    async def test_execute_targets_tool(
        self,
        server_with_mock,
        mock_prometheus,
        mock_targets_response,
    ):
        """Test executing prometheus_get_targets tool."""
        mock_prometheus.get("/api/v1/targets").mock(
            return_value=Response(200, json=mock_targets_response)
        )

        server = server_with_mock

        from prometheus_mcp_server.client import PrometheusClient

        server.client = PrometheusClient(settings=server.settings)
        await server.client.connect()

        try:
            result = await server._execute_tool(
                "prometheus_get_targets",
                {},
            )

            assert "targets" in result
            assert "summary" in result
            assert result["summary"]["health"]["up"] == 1
            assert result["summary"]["health"]["down"] == 1
        finally:
            await server.client.close()

    @pytest.mark.asyncio
    async def test_execute_health_check_tool(
        self,
        server_with_mock,
        mock_prometheus,
    ):
        """Test executing prometheus_health_check tool."""
        mock_prometheus.get("/-/healthy").mock(return_value=Response(200))
        mock_prometheus.get("/-/ready").mock(return_value=Response(200))

        server = server_with_mock

        from prometheus_mcp_server.client import PrometheusClient

        server.client = PrometheusClient(settings=server.settings)
        await server.client.connect()

        try:
            result = await server._execute_tool(
                "prometheus_health_check",
                {},
            )

            assert result["healthy"] is True
            assert result["ready"] is True
            assert "timestamp" in result
        finally:
            await server.client.close()


class TestResultFormatting:
    """Test result formatting functions."""

    def test_format_vector_result(self):
        """Test formatting vector query result."""
        server = create_server()

        raw_result = {
            "resultType": "vector",
            "result": [
                {
                    "metric": {"__name__": "up", "job": "prometheus"},
                    "value": [1704067200, "1"],
                },
            ],
        }

        formatted = server._format_query_result(raw_result)

        assert formatted["resultType"] == "vector"
        assert formatted["resultCount"] == 1
        assert formatted["result"][0]["value"] == "1"
        assert formatted["result"][0]["timestamp"] == 1704067200

    def test_format_matrix_result(self):
        """Test formatting matrix query result."""
        server = create_server()

        raw_result = {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {"__name__": "up", "job": "prometheus"},
                    "values": [
                        [1704067200, "1"],
                        [1704067260, "1"],
                    ],
                },
            ],
        }

        formatted = server._format_query_result(raw_result)

        assert formatted["resultType"] == "matrix"
        assert formatted["resultCount"] == 1
        assert formatted["result"][0]["sample_count"] == 2

    def test_summarize_alerts(self):
        """Test alert summarization."""
        server = create_server()

        alerts = [
            {"state": "firing", "labels": {"severity": "critical"}},
            {"state": "firing", "labels": {"severity": "warning"}},
            {"state": "pending", "labels": {"severity": "warning"}},
        ]

        summary = server._summarize_alerts(alerts)

        assert summary["total"] == 3
        assert summary["by_state"]["firing"] == 2
        assert summary["by_state"]["pending"] == 1
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["warning"] == 2

    def test_summarize_targets(self):
        """Test target summarization."""
        server = create_server()

        targets = {
            "activeTargets": [
                {"health": "up", "labels": {"job": "prometheus"}},
                {"health": "up", "labels": {"job": "node"}},
                {"health": "down", "labels": {"job": "node"}},
            ],
            "droppedTargets": [{"job": "dropped"}],
        }

        summary = server._summarize_targets(targets)

        assert summary["active_count"] == 3
        assert summary["dropped_count"] == 1
        assert summary["health"]["up"] == 2
        assert summary["health"]["down"] == 1
        assert summary["by_job"]["prometheus"]["up"] == 1
        assert summary["by_job"]["node"]["up"] == 1
        assert summary["by_job"]["node"]["down"] == 1
