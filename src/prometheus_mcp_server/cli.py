"""
Command-line interface for Prometheus MCP Server.

Provides a rich CLI with multiple transport options and configuration.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Optional

import click
import structlog
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from prometheus_mcp_server.config import (
    AuthType,
    LogLevel,
    Settings,
    TransportType,
    clear_settings_cache,
)
from prometheus_mcp_server.server import create_server

console = Console()


def setup_logging(level: str, format: str) -> None:
    """Configure structlog for the application."""
    import logging

    # Set up standard logging
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, level.upper()),
        stream=sys.stderr,
    )

    # Configure structlog
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def print_banner() -> None:
    """Print the startup banner."""
    banner = """
[bold blue]Prometheus MCP Server[/bold blue]
[dim]Model Context Protocol server for Prometheus[/dim]
    """
    console.print(Panel(banner, border_style="blue"))


def print_config(settings: Settings) -> None:
    """Print current configuration."""
    table = Table(title="Configuration", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Prometheus URL", settings.url)
    table.add_row("Transport", settings.transport.value)
    table.add_row("Auth Type", settings.auth_type.value)
    table.add_row("TLS Verify", str(settings.tls_verify))
    table.add_row("Timeout", f"{settings.timeout}s")
    table.add_row("Max Retries", str(settings.max_retries))
    table.add_row("Log Level", settings.log_level.value)
    table.add_row("Dangerous Tools", str(settings.enable_dangerous_tools))

    if settings.transport in (TransportType.HTTP, TransportType.SSE):
        table.add_row("Host", settings.host)
        table.add_row("Port", str(settings.port))

    console.print(table)
    console.print()


@click.group(invoke_without_command=True)
@click.option(
    "--url",
    envvar="PROMETHEUS_MCP_URL",
    default="http://localhost:9090",
    help="Prometheus server URL",
)
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http", "sse"]),
    default="stdio",
    help="Transport type: stdio (Claude Desktop), http/sse (AWS AgentCore, K8s)",
)
@click.option(
    "--host",
    default="0.0.0.0",
    help="Host for HTTP/SSE transport (default: 0.0.0.0)",
)
@click.option(
    "--port",
    type=int,
    default=8000,
    help="Port for HTTP transport (default: 8000, MCP standard)",
)
@click.option(
    "--auth-type",
    type=click.Choice(["none", "basic", "bearer", "aws_sigv4"]),
    default="none",
    help="Authentication type",
)
@click.option(
    "--auth-username",
    envvar="PROMETHEUS_MCP_AUTH_USERNAME",
    help="Username for basic auth",
)
@click.option(
    "--auth-password",
    envvar="PROMETHEUS_MCP_AUTH_PASSWORD",
    help="Password for basic auth",
)
@click.option(
    "--auth-token",
    envvar="PROMETHEUS_MCP_AUTH_TOKEN",
    help="Token for bearer auth",
)
@click.option(
    "--aws-region",
    envvar="AWS_REGION",
    help="AWS region for SigV4 auth",
)
@click.option(
    "--aws-profile",
    envvar="AWS_PROFILE",
    help="AWS profile for SigV4 auth",
)
@click.option(
    "--no-tls-verify",
    is_flag=True,
    help="Disable TLS certificate verification",
)
@click.option(
    "--tls-ca-cert",
    type=click.Path(exists=True),
    help="Path to CA certificate",
)
@click.option(
    "--timeout",
    type=float,
    default=30.0,
    help="Request timeout in seconds (default: 30)",
)
@click.option(
    "--max-retries",
    type=int,
    default=3,
    help="Maximum retry attempts (default: 3)",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Log level (default: INFO)",
)
@click.option(
    "--log-format",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Log format (default: text for CLI, json for production)",
)
@click.option(
    "--enable-dangerous-tools",
    is_flag=True,
    help="Enable dangerous tools (delete series, etc.)",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress banner and config output",
)
@click.version_option(version="1.0.0", prog_name="prometheus-mcp-server")
@click.pass_context
def main(
    ctx: click.Context,
    url: str,
    transport: str,
    host: str,
    port: int,
    auth_type: str,
    auth_username: Optional[str],
    auth_password: Optional[str],
    auth_token: Optional[str],
    aws_region: Optional[str],
    aws_profile: Optional[str],
    no_tls_verify: bool,
    tls_ca_cert: Optional[str],
    timeout: float,
    max_retries: int,
    log_level: str,
    log_format: str,
    enable_dangerous_tools: bool,
    quiet: bool,
) -> None:
    """
    Prometheus MCP Server - Model Context Protocol server for Prometheus.

    Provides AI agents with tools to query Prometheus metrics, analyze alerts,
    discover targets, and perform SRE operations.

    \b
    Examples:
      # Run with stdio (for MCP clients like Claude)
      prometheus-mcp-server --url http://prometheus:9090

      # Run as HTTP server for Kubernetes
      prometheus-mcp-server --transport sse --port 8080

      # With basic authentication
      prometheus-mcp-server --auth-type basic \\
        --auth-username admin --auth-password secret

      # With AWS SigV4 for Amazon Managed Prometheus
      prometheus-mcp-server --auth-type aws_sigv4 \\
        --url https://aps-workspaces.us-west-2.amazonaws.com/workspaces/xxx \\
        --aws-region us-west-2
    """
    # If a subcommand is invoked, don't run the server
    if ctx.invoked_subcommand is not None:
        return

    # Clear any cached settings
    clear_settings_cache()

    # Build settings from CLI options
    try:
        settings = Settings(
            url=url,
            transport=TransportType(transport),
            host=host,
            port=port,
            auth_type=AuthType(auth_type),
            auth_username=auth_username,
            auth_password=auth_password,
            auth_token=auth_token,
            aws_region=aws_region,
            aws_profile=aws_profile,
            tls_verify=not no_tls_verify,
            tls_ca_cert=tls_ca_cert,
            timeout=timeout,
            max_retries=max_retries,
            log_level=LogLevel(log_level),
            log_format=log_format,
            enable_dangerous_tools=enable_dangerous_tools,
        )
    except ValueError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(1)

    # Set up logging
    setup_logging(settings.log_level.value, settings.log_format)

    # Print startup info (unless quiet or stdio transport)
    if not quiet and transport != "stdio":
        print_banner()
        print_config(settings)

    # Create and run server
    server = create_server(settings)

    try:
        if settings.transport == TransportType.STDIO:
            asyncio.run(server.run_stdio())
        elif settings.transport in (TransportType.SSE, TransportType.HTTP):
            asyncio.run(server.run_http())
        else:
            console.print(f"[red]Unsupported transport:[/red] {transport}")
            sys.exit(1)
    except KeyboardInterrupt:
        if not quiet:
            console.print("\n[yellow]Shutting down...[/yellow]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@main.command()
@click.option(
    "--url",
    envvar="PROMETHEUS_MCP_URL",
    default="http://localhost:9090",
    help="Prometheus server URL",
)
@click.option(
    "--auth-type",
    type=click.Choice(["none", "basic", "bearer", "aws_sigv4"]),
    default="none",
    help="Authentication type",
)
@click.option(
    "--auth-username",
    envvar="PROMETHEUS_MCP_AUTH_USERNAME",
    help="Username for basic auth",
)
@click.option(
    "--auth-password",
    envvar="PROMETHEUS_MCP_AUTH_PASSWORD",
    help="Password for basic auth",
)
@click.option(
    "--auth-token",
    envvar="PROMETHEUS_MCP_AUTH_TOKEN",
    help="Token for bearer auth",
)
@click.option(
    "--aws-region",
    envvar="AWS_REGION",
    help="AWS region for SigV4 auth",
)
def check(
    url: str,
    auth_type: str,
    auth_username: Optional[str],
    auth_password: Optional[str],
    auth_token: Optional[str],
    aws_region: Optional[str],
) -> None:
    """Check connectivity to Prometheus server."""
    from prometheus_mcp_server.client import PrometheusClient

    console.print(f"[cyan]Checking connection to:[/cyan] {url}")

    try:
        settings = Settings(
            url=url,
            auth_type=AuthType(auth_type),
            auth_username=auth_username,
            auth_password=auth_password,
            auth_token=auth_token,
            aws_region=aws_region,
        )
    except ValueError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(1)

    async def do_check() -> None:
        client = PrometheusClient(settings=settings)
        try:
            await client.connect()

            # Health check
            healthy = await client.health_check()
            ready = await client.ready_check()

            if healthy:
                console.print("[green]✓[/green] Health check passed")
            else:
                console.print("[red]✗[/red] Health check failed")

            if ready:
                console.print("[green]✓[/green] Readiness check passed")
            else:
                console.print("[yellow]![/yellow] Readiness check failed")

            # Get build info
            try:
                build_info = await client.get_status("buildinfo")
                console.print(f"[green]✓[/green] Prometheus version: {build_info.get('version', 'unknown')}")
            except Exception:
                console.print("[yellow]![/yellow] Could not get build info")

            # Test a simple query
            try:
                result = await client.query("up")
                count = len(result.get("result", []))
                console.print(f"[green]✓[/green] Query test passed ({count} series)")
            except Exception as e:
                console.print(f"[red]✗[/red] Query test failed: {e}")

        finally:
            await client.close()

    try:
        asyncio.run(do_check())
        console.print("\n[green]Connection successful![/green]")
    except Exception as e:
        console.print(f"\n[red]Connection failed:[/red] {e}")
        sys.exit(1)


@main.command()
def tools() -> None:
    """List all available MCP tools."""
    table = Table(title="Available Tools", show_header=True)
    table.add_column("Tool", style="cyan", width=35)
    table.add_column("Description", style="white")

    tool_info = [
        ("prometheus_query", "Execute instant PromQL query"),
        ("prometheus_query_range", "Execute range PromQL query"),
        ("prometheus_query_exemplars", "Query exemplars for tracing"),
        ("prometheus_get_alerts", "Get active alerts"),
        ("prometheus_get_alert_rules", "Get alerting rules"),
        ("prometheus_get_targets", "Get scrape targets"),
        ("prometheus_get_target_metadata", "Get target metadata"),
        ("prometheus_get_metric_metadata", "Get metric metadata"),
        ("prometheus_get_label_names", "Get all label names"),
        ("prometheus_get_label_values", "Get values for a label"),
        ("prometheus_series", "Find matching time series"),
        ("prometheus_get_recording_rules", "Get recording rules"),
        ("prometheus_get_status", "Get Prometheus status"),
        ("prometheus_health_check", "Check Prometheus health"),
    ]

    for name, desc in tool_info:
        table.add_row(name, desc)

    console.print(table)
    console.print()

    # Dangerous tools section
    console.print("[yellow]Dangerous Tools (require --enable-dangerous-tools):[/yellow]")
    dangerous_table = Table(show_header=True)
    dangerous_table.add_column("Tool", style="red", width=35)
    dangerous_table.add_column("Description", style="white")

    dangerous_info = [
        ("prometheus_delete_series", "Delete time series data"),
        ("prometheus_clean_tombstones", "Clean deleted data from disk"),
        ("prometheus_snapshot", "Create TSDB snapshot"),
    ]

    for name, desc in dangerous_info:
        dangerous_table.add_row(name, desc)

    console.print(dangerous_table)


@main.command()
@click.option("--format", type=click.Choice(["env", "json", "yaml"]), default="env")
def config_template(format: str) -> None:
    """Generate configuration template."""
    if format == "env":
        template = """# Prometheus MCP Server Configuration
# Copy this to .env and modify as needed

# Prometheus Connection
PROMETHEUS_MCP_URL=http://localhost:9090

# Authentication (none, basic, bearer, aws_sigv4)
PROMETHEUS_MCP_AUTH_TYPE=none
# PROMETHEUS_MCP_AUTH_USERNAME=admin
# PROMETHEUS_MCP_AUTH_PASSWORD=secret
# PROMETHEUS_MCP_AUTH_TOKEN=your-bearer-token

# AWS SigV4 (for Amazon Managed Prometheus)
# AWS_REGION=us-west-2
# AWS_PROFILE=default

# TLS Configuration
PROMETHEUS_MCP_TLS_VERIFY=true
# PROMETHEUS_MCP_TLS_CA_CERT=/path/to/ca.crt
# PROMETHEUS_MCP_TLS_CLIENT_CERT=/path/to/client.crt
# PROMETHEUS_MCP_TLS_CLIENT_KEY=/path/to/client.key

# HTTP Client
PROMETHEUS_MCP_TIMEOUT=30.0
PROMETHEUS_MCP_MAX_RETRIES=3
PROMETHEUS_MCP_RETRY_DELAY=1.0
PROMETHEUS_MCP_MAX_CONNECTIONS=10

# Server (for HTTP/SSE transport)
PROMETHEUS_MCP_TRANSPORT=stdio
PROMETHEUS_MCP_HOST=0.0.0.0
PROMETHEUS_MCP_PORT=8080

# Logging
PROMETHEUS_MCP_LOG_LEVEL=INFO
PROMETHEUS_MCP_LOG_FORMAT=json

# Features
PROMETHEUS_MCP_ENABLE_DANGEROUS_TOOLS=false
PROMETHEUS_MCP_MAX_QUERY_SAMPLES=50000
PROMETHEUS_MCP_DEFAULT_LOOKBACK=1h
PROMETHEUS_MCP_DEFAULT_STEP=1m
"""
    elif format == "json":
        import json as json_module
        template = json_module.dumps({
            "url": "http://localhost:9090",
            "auth_type": "none",
            "tls_verify": True,
            "timeout": 30.0,
            "max_retries": 3,
            "transport": "stdio",
            "host": "0.0.0.0",
            "port": 8080,
            "log_level": "INFO",
            "log_format": "json",
            "enable_dangerous_tools": False,
        }, indent=2)
    else:  # yaml
        template = """# Prometheus MCP Server Configuration
url: http://localhost:9090

# Authentication
auth_type: none  # none, basic, bearer, aws_sigv4
# auth_username: admin
# auth_password: secret
# auth_token: your-bearer-token

# AWS SigV4
# aws_region: us-west-2
# aws_profile: default

# TLS
tls_verify: true
# tls_ca_cert: /path/to/ca.crt
# tls_client_cert: /path/to/client.crt
# tls_client_key: /path/to/client.key

# HTTP Client
timeout: 30.0
max_retries: 3
retry_delay: 1.0
max_connections: 10

# Server
transport: stdio  # stdio, sse, http
host: 0.0.0.0
port: 8080

# Logging
log_level: INFO
log_format: json

# Features
enable_dangerous_tools: false
max_query_samples: 50000
default_lookback: 1h
default_step: 1m
"""

    console.print(template)


if __name__ == "__main__":
    main()
