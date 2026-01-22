# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-01-22

### Added

#### SRE Golden Signals Tools (6 new tools)
- `prometheus_get_error_rate` - Calculate error rate percentage for services
- `prometheus_get_latency_percentiles` - Get p50, p90, p99 latency metrics
- `prometheus_get_throughput` - Calculate requests per second (RPS)
- `prometheus_get_saturation` - Get CPU/memory/disk saturation levels
- `prometheus_calculate_sli` - Calculate SLI and compare against SLO targets
- `prometheus_check_error_budget` - Check error budget consumption status

#### Analysis Tools (5 new tools)
- `prometheus_analyze_service` - Comprehensive service health analysis with all golden signals
- `prometheus_find_anomalies` - Statistical anomaly detection using standard deviation
- `prometheus_compare_periods` - Compare metrics between two time periods
- `prometheus_capacity_forecast` - Predict future capacity needs using linear regression
- `prometheus_find_correlations` - Find Pearson correlation between two metrics

#### PromQL Helper Tools (4 new tools)
- `prometheus_validate_query` - Validate PromQL query syntax
- `prometheus_explain_query` - Explain what a PromQL query does in plain language
- `prometheus_suggest_query` - Get query suggestions for common use cases
- `prometheus_optimize_query` - Get optimization tips for PromQL queries

#### Alertmanager Tools (4 new tools)
- `alertmanager_get_alerts` - Get alerts directly from Alertmanager
- `alertmanager_get_silences` - List all silences with status
- `alertmanager_create_silence` - Create a new silence (requires dangerous tools)
- `alertmanager_delete_silence` - Delete an existing silence (requires dangerous tools)

#### Extended Prometheus API Tools
- `prometheus_get_rules` - Get alerting and recording rules with filtering
- `prometheus_get_metric_names` - List all metric names with search
- `prometheus_find_series` - Find time series matching label selectors
- `prometheus_query_exemplars` - Query exemplars for tracing correlation
- `prometheus_get_target_metadata` - Get metadata about target metrics
- `prometheus_get_alertmanagers` - Get discovered Alertmanager instances

#### Admin/Dangerous Tools
- `prometheus_reload_config` - Trigger Prometheus configuration reload

### Changed
- Total tool count increased from 9 to 38
- Improved async client initialization with proper lock handling
- Enhanced error messages with structured JSON responses
- Updated metrics endpoint to report tool count

### Fixed
- Fixed async event loop issue in `get_client()` function
- Fixed Alertmanager auto-discovery from Prometheus

## [1.0.0] - 2025-01-22

### Added

- Initial release of Prometheus MCP Server
- Complete Prometheus API coverage:
  - Instant queries (`prometheus_query`)
  - Range queries (`prometheus_query_range`)
  - Alerts management (`prometheus_get_alerts`)
  - Target discovery (`prometheus_get_targets`)
  - Metric metadata (`prometheus_get_metric_metadata`, `prometheus_get_label_names`, `prometheus_get_label_values`)
  - Status and health (`prometheus_get_status`, `prometheus_health_check`)
- Multiple authentication methods:
  - No authentication
  - Basic authentication
  - Bearer token authentication
- TLS/SSL support
- Connection pooling and retry logic with exponential backoff
- Multiple transport options:
  - stdio transport for Claude Desktop integration
  - HTTP/SSE transport for Kubernetes deployment
- Kubernetes deployment support:
  - Helm chart
  - Terraform module
  - HPA and PDB
- Dangerous tools (opt-in):
  - `prometheus_delete_series` - Delete time series data
  - `prometheus_clean_tombstones` - Clean deleted data from disk
  - `prometheus_create_snapshot` - Create TSDB snapshot

### Security

- Non-root container execution
- Read-only root filesystem
- Network policies for egress control

[2.0.0]: https://github.com/bcfmtolgahan/prometheus-mcp-server/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/bcfmtolgahan/prometheus-mcp-server/releases/tag/v1.0.0
