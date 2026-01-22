# Prometheus MCP Server

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

A production-grade **Model Context Protocol (MCP) server** for Prometheus, enabling AI agents to query metrics, analyze alerts, and perform SRE operations.

## Features

- **38 MCP Tools**: Complete Prometheus API coverage plus intelligent analysis tools
- **SRE Golden Signals**: Built-in tools for error rate, latency, throughput, and saturation
- **Intelligent Analysis**: Anomaly detection, capacity forecasting, metric correlation
- **PromQL Helpers**: Query validation, explanation, suggestions, and optimization
- **Alertmanager Integration**: Manage alerts and silences
- **Multiple Transports**: stdio (Claude Desktop), HTTP/SSE (Kubernetes, AWS)
- **Production Ready**: Retries, connection pooling, timeouts, TLS support
- **Kubernetes Native**: Helm chart, Terraform module, HPA, PDB

## Quick Start

### Installation

```bash
pip install prometheus-mcp-server
```

### Running with Claude Desktop

Add to your Claude Desktop configuration (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "prometheus": {
      "command": "prometheus-mcp-server",
      "args": ["--url", "http://localhost:9090"]
    }
  }
}
```

### Running as HTTP Server

```bash
# Run with HTTP transport for Kubernetes/AWS deployment
prometheus-mcp-server --transport http --port 8000

# With Prometheus URL
export PROMETHEUS_MCP_URL=http://prometheus:9090
prometheus-mcp-server --transport http
```

### Docker

```bash
docker run -p 8000:8000 \
  -e PROMETHEUS_MCP_URL=http://prometheus:9090 \
  ghcr.io/bcfmtolgahan/prometheus-mcp-server:latest
```

## Available Tools (38 Total)

### Core Query Tools (3)

| Tool | Description |
|------|-------------|
| `prometheus_query` | Execute instant PromQL query |
| `prometheus_query_range` | Execute range PromQL query over time period |
| `prometheus_query_exemplars` | Query exemplars for tracing correlation |

### Alert & Rule Tools (2)

| Tool | Description |
|------|-------------|
| `prometheus_get_alerts` | Get active alerts (firing/pending) |
| `prometheus_get_rules` | Get alerting and recording rules |

### Target Tools (2)

| Tool | Description |
|------|-------------|
| `prometheus_get_targets` | Get scrape targets and health status |
| `prometheus_get_target_metadata` | Get metadata about target metrics |

### Metadata Tools (5)

| Tool | Description |
|------|-------------|
| `prometheus_get_metric_names` | List all metric names |
| `prometheus_get_label_names` | Get all label names |
| `prometheus_get_label_values` | Get values for a specific label |
| `prometheus_get_metric_metadata` | Get metric type, help, unit |
| `prometheus_find_series` | Find time series matching selectors |

### Status & Health Tools (3)

| Tool | Description |
|------|-------------|
| `prometheus_health_check` | Check Prometheus health and readiness |
| `prometheus_get_status` | Get server status (config, flags, runtime, TSDB) |
| `prometheus_get_alertmanagers` | Get discovered Alertmanager instances |

### SRE Golden Signals Tools (6)

| Tool | Description |
|------|-------------|
| `prometheus_get_error_rate` | Calculate error rate percentage |
| `prometheus_get_latency_percentiles` | Get p50, p90, p99 latencies |
| `prometheus_get_throughput` | Calculate requests per second |
| `prometheus_get_saturation` | Get CPU/memory/disk saturation |
| `prometheus_calculate_sli` | Calculate SLI and compare to SLO |
| `prometheus_check_error_budget` | Check error budget consumption |

### Analysis Tools (5)

| Tool | Description |
|------|-------------|
| `prometheus_analyze_service` | Comprehensive service health analysis |
| `prometheus_find_anomalies` | Statistical anomaly detection |
| `prometheus_compare_periods` | Compare metrics between time periods |
| `prometheus_capacity_forecast` | Predict future capacity needs |
| `prometheus_find_correlations` | Find correlations between metrics |

### PromQL Helper Tools (4)

| Tool | Description |
|------|-------------|
| `prometheus_validate_query` | Validate PromQL syntax |
| `prometheus_explain_query` | Explain what a query does |
| `prometheus_suggest_query` | Get query suggestions for use cases |
| `prometheus_optimize_query` | Get query optimization tips |

### Alertmanager Tools (4)

| Tool | Description |
|------|-------------|
| `alertmanager_get_alerts` | Get alerts from Alertmanager |
| `alertmanager_get_silences` | List all silences |
| `alertmanager_create_silence` | Create a new silence |
| `alertmanager_delete_silence` | Delete an existing silence |

### Dangerous/Admin Tools (4)

| Tool | Description |
|------|-------------|
| `prometheus_delete_series` | Delete time series data |
| `prometheus_clean_tombstones` | Clean deleted data from disk |
| `prometheus_create_snapshot` | Create TSDB snapshot |
| `prometheus_reload_config` | Reload Prometheus configuration |

> **Note**: Dangerous tools are disabled by default. Enable with `--enable-dangerous-tools` flag.

## Configuration

### Environment Variables

```bash
# Prometheus Connection
PROMETHEUS_MCP_URL=http://localhost:9090

# Transport
PROMETHEUS_MCP_TRANSPORT=stdio  # stdio, http, sse
PROMETHEUS_MCP_HOST=0.0.0.0
PROMETHEUS_MCP_PORT=8000

# Authentication
PROMETHEUS_MCP_AUTH_TYPE=none  # none, basic, bearer
PROMETHEUS_MCP_AUTH_USERNAME=admin
PROMETHEUS_MCP_AUTH_PASSWORD=secret

# Features
PROMETHEUS_MCP_ENABLE_DANGEROUS_TOOLS=false

# Logging
PROMETHEUS_MCP_LOG_LEVEL=INFO
PROMETHEUS_MCP_LOG_FORMAT=json
```

### CLI Options

```bash
prometheus-mcp-server --help

Options:
  --url TEXT                    Prometheus server URL
  --transport [stdio|http|sse]  Transport type
  --host TEXT                   Host for HTTP transport
  --port INTEGER                Port for HTTP transport
  --enable-dangerous-tools      Enable dangerous admin tools
  --log-level TEXT              Log level
```

## Kubernetes Deployment

### Using Helm

```bash
helm install prometheus-mcp ./deploy/helm/prometheus-mcp-server \
  --set prometheus.url=http://prometheus-server:9090 \
  --set replicaCount=2
```

### Using Terraform

```hcl
module "prometheus_mcp_server" {
  source = "./modules/prometheus-mcp-server"

  prometheus_url = "http://prometheus:9090"
  namespace      = "mcp-servers"
  replica_count  = 2
}
```

## Example Usage

### With Claude Desktop

Ask Claude:
- "What alerts are currently firing?"
- "Show me the CPU usage for the last hour"
- "What's the error rate for the api-gateway service?"
- "Find anomalies in memory usage"
- "Calculate the SLI for our checkout service"

### Programmatic Usage

```python
# Query current cluster health
result = await prometheus_query(query="up")

# Check error rate for a service
error_rate = await prometheus_get_error_rate(job="api-gateway", window="5m")

# Analyze service health
analysis = await prometheus_analyze_service(job="checkout-service")

# Get latency percentiles
latencies = await prometheus_get_latency_percentiles(job="api-gateway")

# Find anomalies
anomalies = await prometheus_find_anomalies(
    query="rate(http_requests_total[5m])",
    threshold_stddev=2.0
)

# Create a silence for maintenance
silence = await alertmanager_create_silence(
    matchers="alertname=HighCPU,job=batch-processor",
    duration="2h",
    comment="Scheduled maintenance"
)
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Client                           │
│              (Claude Desktop, AI Agent)                 │
└────────────────────────┬────────────────────────────────┘
                         │ MCP Protocol (stdio/HTTP)
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Prometheus MCP Server                      │
│  ┌──────────────────────────────────────────────────┐   │
│  │              38 MCP Tools                        │   │
│  │  • Query & Metadata    • SRE Golden Signals      │   │
│  │  • Alerts & Rules      • Analysis Tools          │   │
│  │  • PromQL Helpers      • Alertmanager            │   │
│  └──────────────────────┬───────────────────────────┘   │
│                         │                               │
│  ┌──────────────────────▼───────────────────────────┐   │
│  │              Prometheus Client                   │   │
│  │    • Connection pooling  • Retry logic           │   │
│  │    • Authentication      • TLS support           │   │
│  └──────────────────────┬───────────────────────────┘   │
└─────────────────────────┼───────────────────────────────┘
                          │ HTTP/HTTPS
                          ▼
┌─────────────────────────────────────────────────────────┐
│           Prometheus / Alertmanager                     │
└─────────────────────────────────────────────────────────┘
```

## Development

### Setup

```bash
git clone https://github.com/bcfmtolgahan/prometheus-mcp-server.git
cd prometheus-mcp-server

python -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"
```

### Running Tests

```bash
pytest                           # All tests
pytest --cov                     # With coverage
pytest tests/unit/               # Unit tests only
pytest tests/integration/        # Integration tests
```

### Code Quality

```bash
ruff check .                     # Linting
ruff format .                    # Formatting
mypy src/                        # Type checking
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io/) by Anthropic
- [Prometheus](https://prometheus.io/) by the Cloud Native Computing Foundation
