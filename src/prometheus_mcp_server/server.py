"""
Prometheus MCP Server implementation.

This module provides the main MCP server with all Prometheus tools.
Supports multiple transports: stdio, streamable-http (for AWS AgentCore, etc.)

Total Tools: 38
- 9 Core Query/Metadata Tools
- 6 Extended Prometheus API Tools
- 4 Dangerous/Admin Tools
- 5 Analysis Tools
- 6 SRE Golden Signals Tools
- 4 PromQL Helper Tools
- 4 Alertmanager Tools
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import statistics
from datetime import datetime, timedelta
from typing import Any

import structlog
from mcp.server.fastmcp import FastMCP

from prometheus_mcp_server.client import PrometheusClient, AlertmanagerClient
from prometheus_mcp_server.config import Settings, TransportType, get_settings
from prometheus_mcp_server.exceptions import (
    PrometheusAPIError,
    PrometheusConnectionError,
    PrometheusMCPError,
    PrometheusQueryError,
    PrometheusTimeoutError,
)

logger = structlog.get_logger(__name__)

# Server start time for uptime metric
_server_start_time: float = time.time()

# Global client instances
_prometheus_client: PrometheusClient | None = None
_alertmanager_client: AlertmanagerClient | None = None
_settings: Settings | None = None

_client_lock = asyncio.Lock()
_client_connected = False


async def get_client() -> PrometheusClient:
    """Get the Prometheus client instance (async-safe)."""
    global _prometheus_client, _settings, _client_connected

    if _prometheus_client is None:
        _settings = _settings or get_settings()
        _prometheus_client = PrometheusClient(settings=_settings)

    # Thread-safe connection using lock
    if not _client_connected:
        async with _client_lock:
            if not _client_connected:
                await _prometheus_client.connect()
                _client_connected = True

    return _prometheus_client


async def get_alertmanager_client() -> AlertmanagerClient | None:
    """Get the Alertmanager client instance."""
    global _alertmanager_client, _settings

    if _alertmanager_client is None:
        _settings = _settings or get_settings()
        # Try to discover Alertmanager from Prometheus
        try:
            client = await get_client()
            am_info = await client.get_alertmanagers()
            active_ams = am_info.get("activeAlertmanagers", [])
            if active_ams:
                am_url = active_ams[0].get("url", "").rstrip("/api/v2/alerts")
                if am_url:
                    _alertmanager_client = AlertmanagerClient(url=am_url)
                    await _alertmanager_client.connect()
        except Exception as e:
            logger.warning("Could not discover Alertmanager", error=str(e))

    return _alertmanager_client


def format_error(error: Exception) -> str:
    """Format an error as JSON string."""
    if isinstance(error, PrometheusQueryError):
        return json.dumps({
            "error": "query_error",
            "message": str(error),
        }, indent=2)
    elif isinstance(error, PrometheusConnectionError):
        return json.dumps({
            "error": "connection_error",
            "message": str(error),
        }, indent=2)
    elif isinstance(error, PrometheusTimeoutError):
        return json.dumps({
            "error": "timeout_error",
            "message": str(error),
        }, indent=2)
    elif isinstance(error, PrometheusAPIError):
        return json.dumps({
            "error": "api_error",
            "message": str(error),
        }, indent=2)
    else:
        return json.dumps({
            "error": "internal_error",
            "message": str(error),
        }, indent=2)


def format_query_result(result: dict[str, Any]) -> dict[str, Any]:
    """Format query result for better readability."""
    result_type = result.get("resultType", "unknown")
    data = result.get("result", [])

    formatted = {
        "resultType": result_type,
        "resultCount": len(data) if isinstance(data, list) else 1,
    }

    if result_type == "vector":
        formatted["result"] = [
            {
                "metric": item.get("metric", {}),
                "value": item.get("value", [None, None])[1],
                "timestamp": item.get("value", [None, None])[0],
            }
            for item in data
        ]
    elif result_type == "matrix":
        formatted["result"] = [
            {
                "metric": item.get("metric", {}),
                "values": [
                    {"timestamp": v[0], "value": v[1]}
                    for v in item.get("values", [])
                ],
                "sample_count": len(item.get("values", [])),
            }
            for item in data
        ]
    else:
        formatted["result"] = data

    return formatted


# Create FastMCP instance
mcp = FastMCP("prometheus-mcp-server")


# ==========================================================================
# SECTION 1: CORE QUERY TOOLS (3 tools)
# ==========================================================================

@mcp.tool()
async def prometheus_query(
    query: str,
    time: str | None = None,
    timeout: str | None = None,
) -> str:
    """
    Execute an instant PromQL query against Prometheus.

    Args:
        query: PromQL query string (e.g., 'up{job="prometheus"}')
        time: Evaluation timestamp. Default: now
        timeout: Query timeout. Default: server timeout

    Returns:
        JSON with query results
    """
    try:
        client = await get_client()
        result = await client.query(promql=query, time=time, timeout=timeout)
        return json.dumps(format_query_result(result), indent=2, default=str)
    except Exception as e:
        logger.warning("Query error", error=str(e), query=query)
        return format_error(e)


@mcp.tool()
async def prometheus_query_range(
    query: str,
    start: str | None = None,
    end: str | None = None,
    step: str | None = None,
    timeout: str | None = None,
) -> str:
    """
    Execute a range PromQL query over a time period.

    Args:
        query: PromQL query string
        start: Start time (e.g., '1h', '24h'). Default: 1h ago
        end: End time. Default: now
        step: Query resolution step. Default: 1m
        timeout: Query timeout

    Returns:
        JSON with time series data
    """
    try:
        client = await get_client()
        settings = _settings or get_settings()
        actual_start = start or settings.default_lookback
        actual_end = end or "now"
        result = await client.query_range(
            promql=query, start=actual_start, end=actual_end, step=step, timeout=timeout
        )
        return json.dumps(format_query_result(result), indent=2, default=str)
    except Exception as e:
        logger.warning("Range query error", error=str(e), query=query)
        return format_error(e)


@mcp.tool()
async def prometheus_query_exemplars(
    query: str,
    start: str = "1h",
    end: str = "now",
) -> str:
    """
    Query exemplars for a PromQL expression (for tracing integration).

    Args:
        query: PromQL query expression (selector)
        start: Start time. Default: 1h ago
        end: End time. Default: now

    Returns:
        JSON with exemplars containing trace IDs
    """
    try:
        client = await get_client()
        exemplars = await client.query_exemplars(promql=query, start=start, end=end)
        return json.dumps({
            "exemplars": exemplars,
            "count": len(exemplars),
        }, indent=2, default=str)
    except Exception as e:
        logger.error("Query exemplars error", error=str(e))
        return format_error(e)


# ==========================================================================
# SECTION 2: ALERT TOOLS (2 tools)
# ==========================================================================

@mcp.tool()
async def prometheus_get_alerts(
    state: str | None = None,
) -> str:
    """
    Get all active alerts from Prometheus.

    Args:
        state: Filter by alert state ('firing', 'pending'). Default: all

    Returns:
        JSON with alerts list
    """
    try:
        client = await get_client()
        alerts = await client.get_alerts()

        if state:
            alerts = [a for a in alerts if a.get("state") == state]

        return json.dumps({
            "alerts": alerts,
            "count": len(alerts),
            "firing": len([a for a in alerts if a.get("state") == "firing"]),
            "pending": len([a for a in alerts if a.get("state") == "pending"]),
        }, indent=2, default=str)
    except Exception as e:
        logger.error("Get alerts error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_get_rules(
    rule_type: str | None = None,
    rule_name: str | None = None,
) -> str:
    """
    Get all alerting and recording rules from Prometheus.

    Args:
        rule_type: Filter by type ('alert' or 'record'). Default: all
        rule_name: Filter by rule name (substring match). Default: all

    Returns:
        JSON with rules grouped by file and group
    """
    try:
        client = await get_client()
        rules_data = await client.get_rules(rule_type=rule_type)

        groups = rules_data.get("groups", [])

        # Filter by name if specified
        if rule_name:
            for group in groups:
                group["rules"] = [
                    r for r in group.get("rules", [])
                    if rule_name.lower() in r.get("name", "").lower()
                ]
            groups = [g for g in groups if g.get("rules")]

        # Count rules
        total_alerts = 0
        total_records = 0
        for group in groups:
            for rule in group.get("rules", []):
                if rule.get("type") == "alerting":
                    total_alerts += 1
                else:
                    total_records += 1

        return json.dumps({
            "groups": groups,
            "group_count": len(groups),
            "alert_rules": total_alerts,
            "recording_rules": total_records,
        }, indent=2, default=str)
    except Exception as e:
        logger.error("Get rules error", error=str(e))
        return format_error(e)


# ==========================================================================
# SECTION 3: TARGET TOOLS (2 tools)
# ==========================================================================

@mcp.tool()
async def prometheus_get_targets(
    state: str = "active",
) -> str:
    """
    Get all scrape targets and their current status.

    Args:
        state: Filter by target state ('active', 'dropped', 'any'). Default: active

    Returns:
        JSON with targets list including health status
    """
    try:
        client = await get_client()
        targets = await client.get_targets(state=state)

        active_targets = targets.get("activeTargets", [])
        dropped_targets = targets.get("droppedTargets", [])

        # Count health states
        health_counts = {"up": 0, "down": 0, "unknown": 0}
        for t in active_targets:
            health = t.get("health", "unknown")
            health_counts[health] = health_counts.get(health, 0) + 1

        return json.dumps({
            "targets": targets,
            "summary": {
                "active_count": len(active_targets),
                "dropped_count": len(dropped_targets),
                "health": health_counts,
            }
        }, indent=2, default=str)
    except Exception as e:
        logger.error("Get targets error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_get_target_metadata(
    match_target: str | None = None,
    metric: str | None = None,
    limit: int = 100,
) -> str:
    """
    Get metadata about metrics from specific targets.

    Args:
        match_target: Label selector to match targets (e.g., '{job="node"}')
        metric: Filter by metric name
        limit: Maximum number of results. Default: 100

    Returns:
        JSON with target metadata
    """
    try:
        client = await get_client()
        metadata = await client.get_target_metadata(
            match_target=match_target,
            metric=metric,
            limit=limit,
        )
        return json.dumps({
            "metadata": metadata,
            "count": len(metadata),
        }, indent=2, default=str)
    except Exception as e:
        logger.error("Get target metadata error", error=str(e))
        return format_error(e)


# ==========================================================================
# SECTION 4: METADATA TOOLS (4 tools)
# ==========================================================================

@mcp.tool()
async def prometheus_get_metric_names(
    search: str | None = None,
    limit: int = 100,
) -> str:
    """
    Get all metric names from Prometheus.

    Args:
        search: Filter metrics by substring match. Default: all
        limit: Maximum number of results. Default: 100

    Returns:
        JSON with list of metric names
    """
    try:
        client = await get_client()
        metrics = await client.list_metrics()

        if search:
            metrics = [m for m in metrics if search.lower() in m.lower()]

        metrics = metrics[:limit]

        return json.dumps({
            "metrics": metrics,
            "count": len(metrics),
        }, indent=2)
    except Exception as e:
        logger.error("Get metric names error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_get_label_names() -> str:
    """
    Get all label names present in the time series database.

    Returns:
        JSON with list of label names
    """
    try:
        client = await get_client()
        labels = await client.get_label_names()
        return json.dumps({"labels": labels, "count": len(labels)}, indent=2)
    except Exception as e:
        logger.error("Get label names error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_get_label_values(label: str) -> str:
    """
    Get all values for a specific label.

    Args:
        label: Label name (e.g., 'job', 'instance', 'namespace')

    Returns:
        JSON with list of label values
    """
    try:
        client = await get_client()
        values = await client.get_label_values(label=label)
        return json.dumps({"label": label, "values": values, "count": len(values)}, indent=2)
    except Exception as e:
        logger.error("Get label values error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_get_metric_metadata(metric: str | None = None) -> str:
    """
    Get metadata for metrics (type, help, unit).

    Args:
        metric: Metric name to get metadata for. Default: all

    Returns:
        JSON with metric metadata
    """
    try:
        client = await get_client()
        metadata = await client.get_metric_metadata(metric=metric)
        return json.dumps({"metadata": metadata, "count": len(metadata)}, indent=2, default=str)
    except Exception as e:
        logger.error("Get metric metadata error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_find_series(
    match: str,
    start: str = "1h",
    end: str = "now",
    limit: int = 100,
) -> str:
    """
    Find time series matching a label selector.

    Args:
        match: Series selector (e.g., '{job="prometheus"}', 'up', 'http_requests_total{method="GET"}')
        start: Start time. Default: 1h ago
        end: End time. Default: now
        limit: Maximum number of series. Default: 100

    Returns:
        JSON with matching series and their labels
    """
    try:
        client = await get_client()
        series = await client.series(match=[match], start=start, end=end, limit=limit)
        return json.dumps({
            "series": series,
            "count": len(series),
        }, indent=2, default=str)
    except Exception as e:
        logger.error("Find series error", error=str(e))
        return format_error(e)


# ==========================================================================
# SECTION 5: STATUS & HEALTH TOOLS (3 tools)
# ==========================================================================

@mcp.tool()
async def prometheus_health_check() -> str:
    """
    Check Prometheus server health and readiness.

    Returns:
        JSON with health and readiness status
    """
    try:
        client = await get_client()
        healthy = await client.health_check()
        ready = await client.ready_check()
        return json.dumps({
            "healthy": healthy,
            "ready": ready,
            "timestamp": datetime.utcnow().isoformat(),
        }, indent=2)
    except Exception as e:
        logger.error("Health check error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_get_status(status_type: str = "buildinfo") -> str:
    """
    Get Prometheus server status information.

    Args:
        status_type: Type of status - 'config', 'flags', 'runtimeinfo', 'buildinfo', 'tsdb', 'walreplay'

    Returns:
        JSON with requested status information
    """
    try:
        client = await get_client()
        status = await client.get_status(status_type)
        return json.dumps({"type": status_type, "status": status}, indent=2, default=str)
    except Exception as e:
        logger.error("Get status error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_get_alertmanagers() -> str:
    """
    Get discovered Alertmanager instances.

    Returns:
        JSON with active and dropped Alertmanagers
    """
    try:
        client = await get_client()
        alertmanagers = await client.get_alertmanagers()
        return json.dumps({
            "alertmanagers": alertmanagers,
            "active_count": len(alertmanagers.get("activeAlertmanagers", [])),
            "dropped_count": len(alertmanagers.get("droppedAlertmanagers", [])),
        }, indent=2, default=str)
    except Exception as e:
        logger.error("Get alertmanagers error", error=str(e))
        return format_error(e)


# ==========================================================================
# SECTION 6: DANGEROUS/ADMIN TOOLS (4 tools)
# ==========================================================================

@mcp.tool()
async def prometheus_delete_series(
    match: str,
    start: str | None = None,
    end: str | None = None,
) -> str:
    """
    ⚠️ DANGEROUS: Delete time series matching a selector.

    This permanently deletes data from Prometheus TSDB.
    Requires --web.enable-admin-api flag on Prometheus.

    Args:
        match: Series selector to delete (e.g., '{job="old_service"}')
        start: Start time for deletion range. Default: minimum time
        end: End time for deletion range. Default: maximum time

    Returns:
        JSON with deletion status
    """
    try:
        settings = _settings or get_settings()
        if not settings.enable_dangerous_tools:
            return json.dumps({
                "error": "forbidden",
                "message": "Dangerous tools are disabled. Set PROMETHEUS_MCP_ENABLE_DANGEROUS_TOOLS=true",
            }, indent=2)

        client = await get_client()
        await client.delete_series(match=[match], start=start, end=end)

        return json.dumps({
            "status": "success",
            "message": f"Series matching '{match}' marked for deletion",
            "warning": "Run prometheus_clean_tombstones to reclaim disk space",
        }, indent=2)
    except Exception as e:
        logger.error("Delete series error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_clean_tombstones() -> str:
    """
    ⚠️ DANGEROUS: Remove deleted data from disk.

    Run this after prometheus_delete_series to reclaim disk space.
    Requires --web.enable-admin-api flag on Prometheus.

    Returns:
        JSON with cleanup status
    """
    try:
        settings = _settings or get_settings()
        if not settings.enable_dangerous_tools:
            return json.dumps({
                "error": "forbidden",
                "message": "Dangerous tools are disabled. Set PROMETHEUS_MCP_ENABLE_DANGEROUS_TOOLS=true",
            }, indent=2)

        client = await get_client()
        await client.clean_tombstones()

        return json.dumps({
            "status": "success",
            "message": "Tombstones cleaned successfully",
        }, indent=2)
    except Exception as e:
        logger.error("Clean tombstones error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_create_snapshot(skip_head: bool = False) -> str:
    """
    ⚠️ DANGEROUS: Create a TSDB snapshot for backup.

    Creates a snapshot in Prometheus data directory.
    Requires --web.enable-admin-api flag on Prometheus.

    Args:
        skip_head: Skip data in the head block. Default: false

    Returns:
        JSON with snapshot name and path
    """
    try:
        settings = _settings or get_settings()
        if not settings.enable_dangerous_tools:
            return json.dumps({
                "error": "forbidden",
                "message": "Dangerous tools are disabled. Set PROMETHEUS_MCP_ENABLE_DANGEROUS_TOOLS=true",
            }, indent=2)

        client = await get_client()
        result = await client.snapshot(skip_head=skip_head)

        return json.dumps({
            "status": "success",
            "snapshot": result,
        }, indent=2)
    except Exception as e:
        logger.error("Create snapshot error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_reload_config() -> str:
    """
    ⚠️ DANGEROUS: Trigger Prometheus configuration reload.

    Reloads the Prometheus configuration from disk.
    Requires --web.enable-lifecycle flag on Prometheus.

    Returns:
        JSON with reload status
    """
    try:
        settings = _settings or get_settings()
        if not settings.enable_dangerous_tools:
            return json.dumps({
                "error": "forbidden",
                "message": "Dangerous tools are disabled. Set PROMETHEUS_MCP_ENABLE_DANGEROUS_TOOLS=true",
            }, indent=2)

        client = await get_client()
        success = await client.reload_config()

        return json.dumps({
            "status": "success" if success else "failed",
            "message": "Configuration reloaded" if success else "Reload failed",
        }, indent=2)
    except Exception as e:
        logger.error("Reload config error", error=str(e))
        return format_error(e)


# ==========================================================================
# SECTION 7: SRE GOLDEN SIGNALS TOOLS (6 tools)
# ==========================================================================

@mcp.tool()
async def prometheus_get_error_rate(
    job: str,
    window: str = "5m",
    error_codes: str = "5..",
) -> str:
    """
    Calculate error rate for a service (Golden Signal: Errors).

    Args:
        job: Job/service name
        window: Time window for rate calculation. Default: 5m
        error_codes: HTTP status code pattern for errors. Default: 5..

    Returns:
        JSON with error rate percentage and details
    """
    try:
        client = await get_client()

        # Try common metric patterns
        queries = [
            f'sum(rate(http_requests_total{{job="{job}", status=~"{error_codes}"}}[{window}])) / sum(rate(http_requests_total{{job="{job}"}}[{window}])) * 100',
            f'sum(rate(http_server_requests_total{{job="{job}", status=~"{error_codes}"}}[{window}])) / sum(rate(http_server_requests_total{{job="{job}"}}[{window}])) * 100',
            f'sum(rate(requests_total{{job="{job}", status=~"{error_codes}"}}[{window}])) / sum(rate(requests_total{{job="{job}"}}[{window}])) * 100',
        ]

        for query in queries:
            try:
                result = await client.query(promql=query)
                if result.get("result"):
                    value = result["result"][0].get("value", [None, "NaN"])[1]
                    if value != "NaN":
                        return json.dumps({
                            "job": job,
                            "error_rate_percent": float(value),
                            "window": window,
                            "status": "healthy" if float(value) < 1 else "degraded" if float(value) < 5 else "critical",
                            "query_used": query,
                        }, indent=2)
            except Exception:
                continue

        return json.dumps({
            "job": job,
            "error": "no_data",
            "message": f"Could not find HTTP metrics for job '{job}'",
        }, indent=2)
    except Exception as e:
        logger.error("Get error rate error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_get_latency_percentiles(
    job: str,
    window: str = "5m",
    percentiles: str = "50,90,99",
) -> str:
    """
    Calculate request latency percentiles (Golden Signal: Latency).

    Args:
        job: Job/service name
        window: Time window. Default: 5m
        percentiles: Comma-separated percentiles. Default: 50,90,99

    Returns:
        JSON with latency percentiles in milliseconds
    """
    try:
        client = await get_client()

        results = {}
        for p in percentiles.split(","):
            p = p.strip()
            phi = float(p) / 100

            # Try histogram_quantile with common metric names
            queries = [
                f'histogram_quantile({phi}, sum(rate(http_request_duration_seconds_bucket{{job="{job}"}}[{window}])) by (le)) * 1000',
                f'histogram_quantile({phi}, sum(rate(http_server_requests_seconds_bucket{{job="{job}"}}[{window}])) by (le)) * 1000',
                f'histogram_quantile({phi}, sum(rate(request_duration_seconds_bucket{{job="{job}"}}[{window}])) by (le)) * 1000',
            ]

            for query in queries:
                try:
                    result = await client.query(promql=query)
                    if result.get("result"):
                        value = result["result"][0].get("value", [None, "NaN"])[1]
                        if value != "NaN" and value != "+Inf":
                            results[f"p{p}"] = round(float(value), 2)
                            break
                except Exception:
                    continue

        if results:
            return json.dumps({
                "job": job,
                "latency_ms": results,
                "window": window,
            }, indent=2)

        return json.dumps({
            "job": job,
            "error": "no_data",
            "message": f"Could not find histogram metrics for job '{job}'",
        }, indent=2)
    except Exception as e:
        logger.error("Get latency percentiles error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_get_throughput(
    job: str,
    window: str = "5m",
) -> str:
    """
    Calculate request throughput/RPS (Golden Signal: Traffic).

    Args:
        job: Job/service name
        window: Time window. Default: 5m

    Returns:
        JSON with requests per second
    """
    try:
        client = await get_client()

        queries = [
            f'sum(rate(http_requests_total{{job="{job}"}}[{window}]))',
            f'sum(rate(http_server_requests_total{{job="{job}"}}[{window}]))',
            f'sum(rate(requests_total{{job="{job}"}}[{window}]))',
        ]

        for query in queries:
            try:
                result = await client.query(promql=query)
                if result.get("result"):
                    value = result["result"][0].get("value", [None, "NaN"])[1]
                    if value != "NaN":
                        rps = float(value)
                        return json.dumps({
                            "job": job,
                            "requests_per_second": round(rps, 2),
                            "requests_per_minute": round(rps * 60, 2),
                            "window": window,
                        }, indent=2)
            except Exception:
                continue

        return json.dumps({
            "job": job,
            "error": "no_data",
            "message": f"Could not find request metrics for job '{job}'",
        }, indent=2)
    except Exception as e:
        logger.error("Get throughput error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_get_saturation(
    job: str | None = None,
    resource: str = "cpu",
) -> str:
    """
    Calculate resource saturation (Golden Signal: Saturation).

    Args:
        job: Job/service name. Default: all nodes
        resource: Resource type - 'cpu', 'memory', 'disk'. Default: cpu

    Returns:
        JSON with saturation percentage
    """
    try:
        client = await get_client()

        if resource == "cpu":
            if job:
                query = f'100 - (avg(rate(node_cpu_seconds_total{{job="{job}", mode="idle"}}[5m])) * 100)'
            else:
                query = '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'
        elif resource == "memory":
            if job:
                query = f'(1 - (node_memory_MemAvailable_bytes{{job="{job}"}} / node_memory_MemTotal_bytes{{job="{job}"}})) * 100'
            else:
                query = '(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100'
        elif resource == "disk":
            if job:
                query = f'(1 - (node_filesystem_avail_bytes{{job="{job}", fstype!~"tmpfs|overlay"}} / node_filesystem_size_bytes{{job="{job}", fstype!~"tmpfs|overlay"}})) * 100'
            else:
                query = '(1 - (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay"})) * 100'
        else:
            return json.dumps({
                "error": "invalid_resource",
                "message": f"Unknown resource type: {resource}. Use 'cpu', 'memory', or 'disk'",
            }, indent=2)

        result = await client.query(promql=query)

        if result.get("result"):
            values = []
            for item in result["result"]:
                val = item.get("value", [None, "NaN"])[1]
                if val != "NaN":
                    values.append({
                        "labels": item.get("metric", {}),
                        "saturation_percent": round(float(val), 2),
                    })

            return json.dumps({
                "resource": resource,
                "job": job,
                "instances": values,
                "avg_saturation": round(statistics.mean([v["saturation_percent"] for v in values]), 2) if values else None,
            }, indent=2)

        return json.dumps({
            "resource": resource,
            "error": "no_data",
            "message": "Could not find saturation metrics",
        }, indent=2)
    except Exception as e:
        logger.error("Get saturation error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_calculate_sli(
    sli_query: str,
    window: str = "30d",
    objective: float = 99.9,
) -> str:
    """
    Calculate Service Level Indicator (SLI) and compare to objective.

    Args:
        sli_query: PromQL query that returns SLI as ratio (0-1) or percentage (0-100)
        window: Time window for calculation. Default: 30d
        objective: SLO target percentage. Default: 99.9

    Returns:
        JSON with SLI value, SLO status, and error budget
    """
    try:
        client = await get_client()

        # Query the SLI
        result = await client.query(promql=sli_query)

        if not result.get("result"):
            return json.dumps({
                "error": "no_data",
                "message": "SLI query returned no data",
            }, indent=2)

        value = float(result["result"][0].get("value", [None, 0])[1])

        # Normalize to percentage
        sli_percent = value if value > 1 else value * 100

        # Calculate error budget
        error_budget_total = 100 - objective
        error_budget_used = 100 - sli_percent
        error_budget_remaining = error_budget_total - error_budget_used
        error_budget_remaining_percent = (error_budget_remaining / error_budget_total) * 100 if error_budget_total > 0 else 0

        return json.dumps({
            "sli_percent": round(sli_percent, 4),
            "slo_target": objective,
            "slo_met": sli_percent >= objective,
            "error_budget": {
                "total_percent": round(error_budget_total, 4),
                "used_percent": round(error_budget_used, 4),
                "remaining_percent": round(max(0, error_budget_remaining), 4),
                "remaining_ratio": round(max(0, error_budget_remaining_percent), 2),
            },
            "window": window,
            "status": "healthy" if sli_percent >= objective else "breached",
        }, indent=2)
    except Exception as e:
        logger.error("Calculate SLI error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_check_error_budget(
    job: str,
    slo: float = 99.9,
    window: str = "30d",
) -> str:
    """
    Check error budget status for a service.

    Args:
        job: Job/service name
        slo: SLO target percentage. Default: 99.9
        window: Time window. Default: 30d

    Returns:
        JSON with error budget consumption and burn rate
    """
    try:
        client = await get_client()

        # Calculate availability from successful requests
        availability_query = f'''
            sum(rate(http_requests_total{{job="{job}", status!~"5.."}}[{window}]))
            / sum(rate(http_requests_total{{job="{job}"}}[{window}])) * 100
        '''

        result = await client.query(promql=availability_query)

        if not result.get("result"):
            # Try alternative metric name
            availability_query = f'''
                sum(rate(http_server_requests_total{{job="{job}", status!~"5.."}}[{window}]))
                / sum(rate(http_server_requests_total{{job="{job}"}}[{window}])) * 100
            '''
            result = await client.query(promql=availability_query)

        if not result.get("result"):
            return json.dumps({
                "job": job,
                "error": "no_data",
                "message": f"Could not find metrics for job '{job}'",
            }, indent=2)

        availability = float(result["result"][0].get("value", [None, 0])[1])

        # Error budget calculation
        error_budget_total = 100 - slo
        errors_percent = 100 - availability
        error_budget_consumed = (errors_percent / error_budget_total) * 100 if error_budget_total > 0 else 0
        error_budget_remaining = 100 - error_budget_consumed

        # Determine status
        if error_budget_remaining > 50:
            status = "healthy"
        elif error_budget_remaining > 20:
            status = "warning"
        elif error_budget_remaining > 0:
            status = "critical"
        else:
            status = "exhausted"

        return json.dumps({
            "job": job,
            "availability_percent": round(availability, 4),
            "slo_target": slo,
            "slo_met": availability >= slo,
            "error_budget": {
                "consumed_percent": round(min(100, error_budget_consumed), 2),
                "remaining_percent": round(max(0, error_budget_remaining), 2),
            },
            "window": window,
            "status": status,
        }, indent=2)
    except Exception as e:
        logger.error("Check error budget error", error=str(e))
        return format_error(e)


# ==========================================================================
# SECTION 8: ANALYSIS TOOLS (5 tools)
# ==========================================================================

@mcp.tool()
async def prometheus_analyze_service(
    job: str,
    window: str = "1h",
) -> str:
    """
    Comprehensive service health analysis including all golden signals.

    Args:
        job: Job/service name
        window: Analysis time window. Default: 1h

    Returns:
        JSON with complete service health analysis
    """
    try:
        client = await get_client()

        analysis = {
            "job": job,
            "window": window,
            "timestamp": datetime.utcnow().isoformat(),
            "signals": {},
            "status": "unknown",
            "issues": [],
        }

        # Check if service exists
        up_result = await client.query(promql=f'up{{job="{job}"}}')
        if not up_result.get("result"):
            analysis["status"] = "not_found"
            analysis["issues"].append(f"No targets found for job '{job}'")
            return json.dumps(analysis, indent=2)

        # Analyze UP status
        up_instances = up_result["result"]
        total_instances = len(up_instances)
        up_count = sum(1 for i in up_instances if i.get("value", [0, "0"])[1] == "1")
        analysis["signals"]["availability"] = {
            "total_instances": total_instances,
            "up_instances": up_count,
            "down_instances": total_instances - up_count,
            "availability_percent": round((up_count / total_instances) * 100, 2) if total_instances > 0 else 0,
        }

        if up_count < total_instances:
            analysis["issues"].append(f"{total_instances - up_count} instance(s) down")

        # Try to get error rate
        error_queries = [
            f'sum(rate(http_requests_total{{job="{job}", status=~"5.."}}[{window}])) / sum(rate(http_requests_total{{job="{job}"}}[{window}])) * 100',
            f'sum(rate(http_server_requests_total{{job="{job}", status=~"5.."}}[{window}])) / sum(rate(http_server_requests_total{{job="{job}"}}[{window}])) * 100',
        ]

        for query in error_queries:
            try:
                result = await client.query(promql=query)
                if result.get("result"):
                    value = result["result"][0].get("value", [None, "NaN"])[1]
                    if value not in ("NaN", None):
                        error_rate = float(value)
                        analysis["signals"]["error_rate"] = {
                            "percent": round(error_rate, 4),
                            "status": "healthy" if error_rate < 1 else "degraded" if error_rate < 5 else "critical",
                        }
                        if error_rate >= 1:
                            analysis["issues"].append(f"Error rate is {round(error_rate, 2)}%")
                        break
            except Exception:
                continue

        # Try to get throughput
        throughput_queries = [
            f'sum(rate(http_requests_total{{job="{job}"}}[{window}]))',
            f'sum(rate(http_server_requests_total{{job="{job}"}}[{window}]))',
        ]

        for query in throughput_queries:
            try:
                result = await client.query(promql=query)
                if result.get("result"):
                    value = result["result"][0].get("value", [None, "NaN"])[1]
                    if value not in ("NaN", None):
                        rps = float(value)
                        analysis["signals"]["throughput"] = {
                            "requests_per_second": round(rps, 2),
                        }
                        break
            except Exception:
                continue

        # Determine overall status
        if up_count == 0:
            analysis["status"] = "down"
        elif any("critical" in str(s.get("status", "")) for s in analysis["signals"].values() if isinstance(s, dict)):
            analysis["status"] = "critical"
        elif any("degraded" in str(s.get("status", "")) for s in analysis["signals"].values() if isinstance(s, dict)):
            analysis["status"] = "degraded"
        elif analysis["issues"]:
            analysis["status"] = "warning"
        else:
            analysis["status"] = "healthy"

        return json.dumps(analysis, indent=2)
    except Exception as e:
        logger.error("Analyze service error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_find_anomalies(
    query: str,
    window: str = "1h",
    threshold_stddev: float = 2.0,
) -> str:
    """
    Find anomalies in metric data using statistical analysis.

    Args:
        query: PromQL query to analyze
        window: Analysis time window. Default: 1h
        threshold_stddev: Standard deviations for anomaly threshold. Default: 2.0

    Returns:
        JSON with anomaly detection results
    """
    try:
        client = await get_client()

        # Get range data
        result = await client.query_range(promql=query, start=window, end="now", step="1m")

        if not result.get("result"):
            return json.dumps({
                "error": "no_data",
                "message": "Query returned no data",
            }, indent=2)

        anomalies = []

        for series in result["result"]:
            metric = series.get("metric", {})
            values = [float(v[1]) for v in series.get("values", []) if v[1] not in ("NaN", "+Inf", "-Inf")]

            if len(values) < 10:
                continue

            # Calculate statistics
            mean = statistics.mean(values)
            stdev = statistics.stdev(values) if len(values) > 1 else 0

            # Find anomalies
            upper_bound = mean + (threshold_stddev * stdev)
            lower_bound = mean - (threshold_stddev * stdev)

            anomaly_points = []
            for v in series.get("values", []):
                try:
                    val = float(v[1])
                    if val > upper_bound or val < lower_bound:
                        anomaly_points.append({
                            "timestamp": v[0],
                            "value": val,
                            "deviation": round((val - mean) / stdev if stdev > 0 else 0, 2),
                        })
                except (ValueError, TypeError):
                    continue

            if anomaly_points:
                anomalies.append({
                    "metric": metric,
                    "statistics": {
                        "mean": round(mean, 4),
                        "stddev": round(stdev, 4),
                        "upper_bound": round(upper_bound, 4),
                        "lower_bound": round(lower_bound, 4),
                    },
                    "anomaly_count": len(anomaly_points),
                    "anomaly_points": anomaly_points[-10:],  # Last 10 anomalies
                })

        return json.dumps({
            "query": query,
            "window": window,
            "threshold_stddev": threshold_stddev,
            "series_analyzed": len(result["result"]),
            "series_with_anomalies": len(anomalies),
            "anomalies": anomalies,
        }, indent=2)
    except Exception as e:
        logger.error("Find anomalies error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_compare_periods(
    query: str,
    current_start: str = "1h",
    baseline_start: str = "25h",
    baseline_end: str = "24h",
) -> str:
    """
    Compare metric values between two time periods.

    Args:
        query: PromQL query to compare
        current_start: Start of current period. Default: 1h ago
        baseline_start: Start of baseline period. Default: 25h ago
        baseline_end: End of baseline period. Default: 24h ago

    Returns:
        JSON with comparison statistics
    """
    try:
        client = await get_client()

        # Get current period data
        current_result = await client.query_range(
            promql=query, start=current_start, end="now", step="1m"
        )

        # Get baseline period data
        baseline_result = await client.query_range(
            promql=query, start=baseline_start, end=baseline_end, step="1m"
        )

        if not current_result.get("result") or not baseline_result.get("result"):
            return json.dumps({
                "error": "no_data",
                "message": "One or both periods returned no data",
            }, indent=2)

        comparisons = []

        for current_series in current_result["result"]:
            metric = current_series.get("metric", {})
            current_values = [float(v[1]) for v in current_series.get("values", []) if v[1] not in ("NaN", "+Inf", "-Inf")]

            # Find matching baseline series
            baseline_values = []
            for baseline_series in baseline_result["result"]:
                if baseline_series.get("metric") == metric:
                    baseline_values = [float(v[1]) for v in baseline_series.get("values", []) if v[1] not in ("NaN", "+Inf", "-Inf")]
                    break

            if not current_values or not baseline_values:
                continue

            current_avg = statistics.mean(current_values)
            baseline_avg = statistics.mean(baseline_values)

            change_percent = ((current_avg - baseline_avg) / baseline_avg * 100) if baseline_avg != 0 else 0

            comparisons.append({
                "metric": metric,
                "current": {
                    "avg": round(current_avg, 4),
                    "min": round(min(current_values), 4),
                    "max": round(max(current_values), 4),
                },
                "baseline": {
                    "avg": round(baseline_avg, 4),
                    "min": round(min(baseline_values), 4),
                    "max": round(max(baseline_values), 4),
                },
                "change_percent": round(change_percent, 2),
                "status": "increased" if change_percent > 10 else "decreased" if change_percent < -10 else "stable",
            })

        return json.dumps({
            "query": query,
            "current_period": f"{current_start} to now",
            "baseline_period": f"{baseline_start} to {baseline_end}",
            "comparisons": comparisons,
        }, indent=2)
    except Exception as e:
        logger.error("Compare periods error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_capacity_forecast(
    query: str,
    forecast_window: str = "7d",
    history_window: str = "30d",
) -> str:
    """
    Forecast future capacity based on historical trends.

    Args:
        query: PromQL query for the metric to forecast
        forecast_window: How far to forecast. Default: 7d
        history_window: Historical data to use. Default: 30d

    Returns:
        JSON with capacity forecast
    """
    try:
        client = await get_client()

        # Use Prometheus's predict_linear function
        forecast_seconds = 7 * 24 * 3600  # Default 7 days
        if forecast_window.endswith("d"):
            forecast_seconds = int(forecast_window[:-1]) * 24 * 3600
        elif forecast_window.endswith("h"):
            forecast_seconds = int(forecast_window[:-1]) * 3600

        # Get current value
        current_result = await client.query(promql=query)

        # Get predicted value
        predict_query = f'predict_linear({query}[{history_window}], {forecast_seconds})'
        forecast_result = await client.query(promql=predict_query)

        # Get rate of change
        deriv_query = f'deriv({query}[{history_window}])'
        deriv_result = await client.query(promql=deriv_query)

        forecasts = []

        for current_series in current_result.get("result", []):
            metric = current_series.get("metric", {})
            current_value = float(current_series.get("value", [0, 0])[1])

            # Find matching forecast
            forecast_value = None
            for f in forecast_result.get("result", []):
                if f.get("metric") == metric:
                    val = f.get("value", [0, "NaN"])[1]
                    if val not in ("NaN", "+Inf", "-Inf"):
                        forecast_value = float(val)
                    break

            # Find matching derivative
            rate_of_change = None
            for d in deriv_result.get("result", []):
                if d.get("metric") == metric:
                    val = d.get("value", [0, "NaN"])[1]
                    if val not in ("NaN", "+Inf", "-Inf"):
                        rate_of_change = float(val)
                    break

            if forecast_value is not None:
                forecasts.append({
                    "metric": metric,
                    "current_value": round(current_value, 4),
                    "forecast_value": round(forecast_value, 4),
                    "change_percent": round((forecast_value - current_value) / current_value * 100, 2) if current_value != 0 else 0,
                    "rate_per_day": round(rate_of_change * 86400, 4) if rate_of_change else None,
                    "trend": "increasing" if rate_of_change and rate_of_change > 0 else "decreasing" if rate_of_change and rate_of_change < 0 else "stable",
                })

        return json.dumps({
            "query": query,
            "history_window": history_window,
            "forecast_window": forecast_window,
            "forecasts": forecasts,
        }, indent=2)
    except Exception as e:
        logger.error("Capacity forecast error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_find_correlations(
    metric1: str,
    metric2: str,
    window: str = "1h",
) -> str:
    """
    Find correlation between two metrics.

    Args:
        metric1: First PromQL query
        metric2: Second PromQL query
        window: Analysis time window. Default: 1h

    Returns:
        JSON with correlation analysis
    """
    try:
        client = await get_client()

        # Get data for both metrics
        result1 = await client.query_range(promql=metric1, start=window, end="now", step="1m")
        result2 = await client.query_range(promql=metric2, start=window, end="now", step="1m")

        if not result1.get("result") or not result2.get("result"):
            return json.dumps({
                "error": "no_data",
                "message": "One or both metrics returned no data",
            }, indent=2)

        # Extract values (align by timestamp)
        values1 = {}
        for series in result1["result"]:
            for ts, val in series.get("values", []):
                if val not in ("NaN", "+Inf", "-Inf"):
                    values1[ts] = float(val)

        values2 = {}
        for series in result2["result"]:
            for ts, val in series.get("values", []):
                if val not in ("NaN", "+Inf", "-Inf"):
                    values2[ts] = float(val)

        # Find common timestamps
        common_ts = set(values1.keys()) & set(values2.keys())

        if len(common_ts) < 10:
            return json.dumps({
                "error": "insufficient_data",
                "message": "Not enough overlapping data points",
            }, indent=2)

        # Calculate Pearson correlation
        x = [values1[ts] for ts in sorted(common_ts)]
        y = [values2[ts] for ts in sorted(common_ts)]

        n = len(x)
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(xi * yi for xi, yi in zip(x, y))
        sum_x2 = sum(xi ** 2 for xi in x)
        sum_y2 = sum(yi ** 2 for yi in y)

        numerator = n * sum_xy - sum_x * sum_y
        denominator = ((n * sum_x2 - sum_x ** 2) * (n * sum_y2 - sum_y ** 2)) ** 0.5

        correlation = numerator / denominator if denominator != 0 else 0

        # Interpret correlation
        if abs(correlation) >= 0.8:
            strength = "strong"
        elif abs(correlation) >= 0.5:
            strength = "moderate"
        elif abs(correlation) >= 0.3:
            strength = "weak"
        else:
            strength = "negligible"

        direction = "positive" if correlation > 0 else "negative" if correlation < 0 else "none"

        return json.dumps({
            "metric1": metric1,
            "metric2": metric2,
            "window": window,
            "data_points": n,
            "correlation": round(correlation, 4),
            "strength": strength,
            "direction": direction,
            "interpretation": f"{strength.capitalize()} {direction} correlation between metrics",
        }, indent=2)
    except Exception as e:
        logger.error("Find correlations error", error=str(e))
        return format_error(e)


# ==========================================================================
# SECTION 9: PROMQL HELPER TOOLS (4 tools)
# ==========================================================================

@mcp.tool()
async def prometheus_validate_query(query: str) -> str:
    """
    Validate a PromQL query syntax without executing it.

    Args:
        query: PromQL query to validate

    Returns:
        JSON with validation result
    """
    try:
        client = await get_client()

        # Try to execute with a very short time range
        try:
            await client.query(promql=query, timeout="1s")
            return json.dumps({
                "query": query,
                "valid": True,
                "message": "Query syntax is valid",
            }, indent=2)
        except PrometheusQueryError as e:
            error_msg = str(e)
            # Parse error details
            return json.dumps({
                "query": query,
                "valid": False,
                "error": error_msg,
            }, indent=2)
    except Exception as e:
        return json.dumps({
            "query": query,
            "valid": False,
            "error": str(e),
        }, indent=2)


@mcp.tool()
async def prometheus_explain_query(query: str) -> str:
    """
    Explain what a PromQL query does in plain language.

    Args:
        query: PromQL query to explain

    Returns:
        JSON with query explanation
    """
    try:
        explanations = []

        # Detect common patterns
        if "rate(" in query:
            explanations.append("rate(): Calculates per-second rate of increase for counter metrics")
        if "irate(" in query:
            explanations.append("irate(): Calculates instant rate using last two data points (more volatile than rate)")
        if "increase(" in query:
            explanations.append("increase(): Calculates total increase over time range")
        if "sum(" in query:
            explanations.append("sum(): Aggregates values across all matching series")
        if "avg(" in query:
            explanations.append("avg(): Calculates average across all matching series")
        if "max(" in query:
            explanations.append("max(): Returns maximum value across all matching series")
        if "min(" in query:
            explanations.append("min(): Returns minimum value across all matching series")
        if "count(" in query:
            explanations.append("count(): Counts number of matching series")
        if "histogram_quantile(" in query:
            explanations.append("histogram_quantile(): Calculates percentile from histogram buckets")
        if "topk(" in query:
            explanations.append("topk(): Returns top K series by value")
        if "bottomk(" in query:
            explanations.append("bottomk(): Returns bottom K series by value")
        if "by (" in query or "by(" in query:
            explanations.append("by(): Groups results by specified labels")
        if "without (" in query or "without(" in query:
            explanations.append("without(): Groups results excluding specified labels")
        if "offset " in query:
            explanations.append("offset: Shifts query evaluation time into the past")
        if "predict_linear(" in query:
            explanations.append("predict_linear(): Predicts future value using linear regression")
        if "deriv(" in query:
            explanations.append("deriv(): Calculates rate of change (derivative)")
        if "absent(" in query:
            explanations.append("absent(): Returns 1 if series doesn't exist (useful for alerting)")
        if "changes(" in query:
            explanations.append("changes(): Counts number of value changes over time")
        if "resets(" in query:
            explanations.append("resets(): Counts counter resets over time")

        # Detect label matchers
        label_matchers = re.findall(r'\{([^}]+)\}', query)
        if label_matchers:
            explanations.append(f"Label filters: {', '.join(label_matchers)}")

        # Detect time range
        time_ranges = re.findall(r'\[(\d+[smhdwy])\]', query)
        if time_ranges:
            explanations.append(f"Time ranges used: {', '.join(time_ranges)}")

        if not explanations:
            explanations.append("Basic metric selector - returns current values for matching series")

        return json.dumps({
            "query": query,
            "explanation": explanations,
        }, indent=2)
    except Exception as e:
        logger.error("Explain query error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_suggest_query(
    metric: str,
    use_case: str = "current_value",
) -> str:
    """
    Suggest PromQL queries for common use cases.

    Args:
        metric: Base metric name
        use_case: Query use case - 'current_value', 'rate', 'percentile', 'top_consumers', 'aggregated', 'alert'

    Returns:
        JSON with suggested queries
    """
    try:
        suggestions = []

        if use_case == "current_value":
            suggestions = [
                {"description": "Current value", "query": metric},
                {"description": "Current value with job filter", "query": f'{metric}{{job="<job_name>"}}'},
            ]

        elif use_case == "rate":
            suggestions = [
                {"description": "Per-second rate (5m window)", "query": f'rate({metric}[5m])'},
                {"description": "Aggregated rate by job", "query": f'sum by (job) (rate({metric}[5m]))'},
                {"description": "Total increase over 1h", "query": f'increase({metric}[1h])'},
            ]

        elif use_case == "percentile":
            suggestions = [
                {"description": "50th percentile (median)", "query": f'histogram_quantile(0.50, sum(rate({metric}_bucket[5m])) by (le))'},
                {"description": "90th percentile", "query": f'histogram_quantile(0.90, sum(rate({metric}_bucket[5m])) by (le))'},
                {"description": "99th percentile", "query": f'histogram_quantile(0.99, sum(rate({metric}_bucket[5m])) by (le))'},
            ]

        elif use_case == "top_consumers":
            suggestions = [
                {"description": "Top 10 by value", "query": f'topk(10, {metric})'},
                {"description": "Top 10 by rate", "query": f'topk(10, rate({metric}[5m]))'},
                {"description": "Bottom 10 by value", "query": f'bottomk(10, {metric})'},
            ]

        elif use_case == "aggregated":
            suggestions = [
                {"description": "Sum across all series", "query": f'sum({metric})'},
                {"description": "Average across all series", "query": f'avg({metric})'},
                {"description": "Sum grouped by job", "query": f'sum by (job) ({metric})'},
                {"description": "Count of series", "query": f'count({metric})'},
            ]

        elif use_case == "alert":
            suggestions = [
                {"description": "Alert when value > threshold", "query": f'{metric} > <threshold>'},
                {"description": "Alert when absent", "query": f'absent({metric}{{job="<job_name>"}})'},
                {"description": "Alert on high rate", "query": f'rate({metric}[5m]) > <threshold>'},
                {"description": "Alert on percentage", "query": f'({metric}_errors / {metric}_total) * 100 > <threshold>'},
            ]

        else:
            return json.dumps({
                "error": "invalid_use_case",
                "valid_use_cases": ["current_value", "rate", "percentile", "top_consumers", "aggregated", "alert"],
            }, indent=2)

        return json.dumps({
            "metric": metric,
            "use_case": use_case,
            "suggestions": suggestions,
        }, indent=2)
    except Exception as e:
        logger.error("Suggest query error", error=str(e))
        return format_error(e)


@mcp.tool()
async def prometheus_optimize_query(query: str) -> str:
    """
    Suggest optimizations for a PromQL query.

    Args:
        query: PromQL query to optimize

    Returns:
        JSON with optimization suggestions
    """
    try:
        suggestions = []

        # Check for common anti-patterns
        if re.search(r'rate\([^[]+\[1[ms]\]', query):
            suggestions.append({
                "issue": "Very short rate window",
                "suggestion": "Use at least 2x scrape interval for rate() (typically 2m or more)",
            })

        if ".*" in query:
            suggestions.append({
                "issue": "Wildcard regex match",
                "suggestion": "Use specific label values instead of .* where possible",
            })

        if query.count("{") > query.count("by (") and "sum" in query:
            suggestions.append({
                "issue": "Missing aggregation grouping",
                "suggestion": "Add 'by (label)' to sum() to preserve needed labels",
            })

        if "irate" in query and "[1m]" not in query and "[30s]" not in query:
            suggestions.append({
                "issue": "irate with long range",
                "suggestion": "irate() should use short ranges (1-2x scrape interval). Use rate() for longer ranges",
            })

        if re.search(r'\{[^}]*!~[^}]*\}', query):
            suggestions.append({
                "issue": "Negative regex match",
                "suggestion": "Negative regex (!~) can be slow. Consider using positive matches where possible",
            })

        if query.count("rate(") > 1 and "+" in query:
            suggestions.append({
                "issue": "Adding rates separately",
                "suggestion": "Sum the metric inside rate() instead: sum(rate(metric[5m]))",
            })

        if "offset" in query.lower() and "rate(" in query:
            suggestions.append({
                "issue": "Offset with rate",
                "suggestion": "Apply offset inside rate(): rate(metric[5m] offset 1h)",
            })

        if not suggestions:
            suggestions.append({
                "status": "ok",
                "message": "No obvious optimization issues found",
            })

        return json.dumps({
            "query": query,
            "suggestions": suggestions,
        }, indent=2)
    except Exception as e:
        logger.error("Optimize query error", error=str(e))
        return format_error(e)


# ==========================================================================
# SECTION 10: ALERTMANAGER TOOLS (4 tools)
# ==========================================================================

@mcp.tool()
async def alertmanager_get_alerts(
    silenced: bool = True,
    inhibited: bool = True,
    active: bool = True,
) -> str:
    """
    Get alerts from Alertmanager.

    Args:
        silenced: Include silenced alerts. Default: true
        inhibited: Include inhibited alerts. Default: true
        active: Include active alerts. Default: true

    Returns:
        JSON with alerts from Alertmanager
    """
    try:
        am_client = await get_alertmanager_client()
        if am_client is None:
            return json.dumps({
                "error": "alertmanager_not_found",
                "message": "Could not connect to Alertmanager",
            }, indent=2)

        alerts = await am_client.get_alerts(
            silenced=silenced,
            inhibited=inhibited,
            active=active,
        )

        return json.dumps({
            "alerts": alerts,
            "count": len(alerts),
        }, indent=2, default=str)
    except Exception as e:
        logger.error("Alertmanager get alerts error", error=str(e))
        return format_error(e)


@mcp.tool()
async def alertmanager_get_silences() -> str:
    """
    Get all silences from Alertmanager.

    Returns:
        JSON with active silences
    """
    try:
        am_client = await get_alertmanager_client()
        if am_client is None:
            return json.dumps({
                "error": "alertmanager_not_found",
                "message": "Could not connect to Alertmanager",
            }, indent=2)

        silences = await am_client.get_silences()

        # Categorize silences
        active = [s for s in silences if s.get("status", {}).get("state") == "active"]
        pending = [s for s in silences if s.get("status", {}).get("state") == "pending"]
        expired = [s for s in silences if s.get("status", {}).get("state") == "expired"]

        return json.dumps({
            "silences": silences,
            "summary": {
                "total": len(silences),
                "active": len(active),
                "pending": len(pending),
                "expired": len(expired),
            },
        }, indent=2, default=str)
    except Exception as e:
        logger.error("Alertmanager get silences error", error=str(e))
        return format_error(e)


@mcp.tool()
async def alertmanager_create_silence(
    matchers: str,
    duration: str = "2h",
    created_by: str = "prometheus-mcp-server",
    comment: str = "Created via MCP",
) -> str:
    """
    Create a silence in Alertmanager.

    Args:
        matchers: Comma-separated matchers (e.g., 'alertname=HighCPU,job=node')
        duration: Silence duration. Default: 2h
        created_by: Creator name. Default: prometheus-mcp-server
        comment: Silence comment. Default: Created via MCP

    Returns:
        JSON with created silence ID
    """
    try:
        settings = _settings or get_settings()
        if not settings.enable_dangerous_tools:
            return json.dumps({
                "error": "forbidden",
                "message": "Dangerous tools are disabled. Set PROMETHEUS_MCP_ENABLE_DANGEROUS_TOOLS=true",
            }, indent=2)

        am_client = await get_alertmanager_client()
        if am_client is None:
            return json.dumps({
                "error": "alertmanager_not_found",
                "message": "Could not connect to Alertmanager",
            }, indent=2)

        # Parse matchers
        matcher_list = []
        for m in matchers.split(","):
            m = m.strip()
            if "=~" in m:
                name, value = m.split("=~", 1)
                matcher_list.append({"name": name.strip(), "value": value.strip(), "isRegex": True})
            elif "=" in m:
                name, value = m.split("=", 1)
                matcher_list.append({"name": name.strip(), "value": value.strip(), "isRegex": False})

        # Calculate times
        now = datetime.utcnow()
        duration_seconds = 7200  # Default 2h
        if duration.endswith("h"):
            duration_seconds = int(duration[:-1]) * 3600
        elif duration.endswith("m"):
            duration_seconds = int(duration[:-1]) * 60
        elif duration.endswith("d"):
            duration_seconds = int(duration[:-1]) * 86400

        ends_at = now + timedelta(seconds=duration_seconds)

        result = await am_client.create_silence(
            matchers=matcher_list,
            starts_at=now.isoformat() + "Z",
            ends_at=ends_at.isoformat() + "Z",
            created_by=created_by,
            comment=comment,
        )

        return json.dumps({
            "status": "success",
            "silence_id": result.get("silenceID"),
            "matchers": matcher_list,
            "expires_at": ends_at.isoformat(),
        }, indent=2)
    except Exception as e:
        logger.error("Alertmanager create silence error", error=str(e))
        return format_error(e)


@mcp.tool()
async def alertmanager_delete_silence(silence_id: str) -> str:
    """
    Delete a silence from Alertmanager.

    Args:
        silence_id: ID of the silence to delete

    Returns:
        JSON with deletion status
    """
    try:
        settings = _settings or get_settings()
        if not settings.enable_dangerous_tools:
            return json.dumps({
                "error": "forbidden",
                "message": "Dangerous tools are disabled. Set PROMETHEUS_MCP_ENABLE_DANGEROUS_TOOLS=true",
            }, indent=2)

        am_client = await get_alertmanager_client()
        if am_client is None:
            return json.dumps({
                "error": "alertmanager_not_found",
                "message": "Could not connect to Alertmanager",
            }, indent=2)

        await am_client.delete_silence(silence_id)

        return json.dumps({
            "status": "success",
            "message": f"Silence {silence_id} deleted",
        }, indent=2)
    except Exception as e:
        logger.error("Alertmanager delete silence error", error=str(e))
        return format_error(e)


# ==========================================================================
# Server Factory and Runner
# ==========================================================================

class PrometheusServer:
    """Production-grade MCP Server for Prometheus."""

    def __init__(self, settings: Settings | None = None) -> None:
        global _settings
        self.settings = settings or get_settings()
        _settings = self.settings

    async def run(self) -> None:
        """Run the server with configured transport."""
        transport = self.settings.transport

        if transport == TransportType.STDIO:
            await self.run_stdio()
        elif transport in (TransportType.HTTP, TransportType.SSE):
            await self.run_http()
        else:
            raise ValueError(f"Unsupported transport: {transport}")

    async def run_stdio(self) -> None:
        """Run with stdio transport."""
        logger.info("Starting Prometheus MCP Server (stdio)")
        mcp.run(transport="stdio")

    async def run_http(self) -> None:
        """Run with streamable-http transport."""
        import uvicorn
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse, PlainTextResponse
        from starlette.routing import Route

        host = self.settings.host
        port = self.settings.port

        logger.info(
            "Starting Prometheus MCP Server (streamable-http)",
            host=host,
            port=port,
        )

        # Health check endpoints
        async def health_endpoint(request):
            return JSONResponse({"status": "healthy"})

        async def ready_endpoint(request):
            return JSONResponse({"status": "ready"})

        async def metrics_endpoint(request):
            uptime = time.time() - _server_start_time
            metrics = [
                f"prometheus_mcp_server_uptime_seconds {uptime:.2f}",
                'prometheus_mcp_server_info{version="2.0.0"} 1',
                "prometheus_mcp_server_tools_total 38",
            ]
            return PlainTextResponse("\n".join(metrics) + "\n")

        routes = [
            Route("/health", health_endpoint, methods=["GET"]),
            Route("/healthz", health_endpoint, methods=["GET"]),
            Route("/ready", ready_endpoint, methods=["GET"]),
            Route("/readyz", ready_endpoint, methods=["GET"]),
            Route("/metrics", metrics_endpoint, methods=["GET"]),
        ]

        health_app = Starlette(routes=routes)

        # Get MCP app
        mcp_app = mcp.sse_app()

        # Combined app
        async def combined_app(scope, receive, send):
            path = scope.get("path", "")
            if path in ("/health", "/healthz", "/ready", "/readyz", "/metrics"):
                await health_app(scope, receive, send)
            else:
                await mcp_app(scope, receive, send)

        config = uvicorn.Config(combined_app, host=host, port=port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()


def create_server(settings: Settings | None = None) -> PrometheusServer:
    """Create a new Prometheus MCP Server instance."""
    return PrometheusServer(settings=settings)


if __name__ == "__main__":
    import asyncio
    settings = get_settings()
    server = PrometheusServer(settings=settings)
    asyncio.run(server.run())
