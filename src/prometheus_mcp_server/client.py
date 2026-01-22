"""
Prometheus HTTP API client with retry logic, connection pooling, and error handling.
"""

from __future__ import annotations

import ssl
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Optional, Union
from urllib.parse import urljoin

import httpx
import structlog
from dateutil import parser as date_parser
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from prometheus_mcp_server.config import AuthType, Settings, get_settings
from prometheus_mcp_server.exceptions import (
    PrometheusAPIError,
    PrometheusConnectionError,
    PrometheusQueryError,
    PrometheusTimeoutError,
)

logger = structlog.get_logger(__name__)


class PrometheusClient:
    """
    Async Prometheus HTTP API client.

    Features:
    - Async HTTP with connection pooling
    - Automatic retries with exponential backoff
    - Multiple authentication methods (basic, bearer, AWS SigV4)
    - TLS/SSL support
    - Comprehensive error handling

    Example:
        ```python
        async with PrometheusClient() as client:
            result = await client.query("up")
            print(result)
        ```
    """

    def __init__(self, settings: Optional[Settings] = None) -> None:
        """
        Initialize Prometheus client.

        Args:
            settings: Configuration settings. Uses default settings if not provided.
        """
        self.settings = settings or get_settings()
        self._client: Optional[httpx.AsyncClient] = None
        self._log = logger.bind(prometheus_url=self.settings.url)

    async def __aenter__(self) -> "PrometheusClient":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

    async def connect(self) -> None:
        """Establish connection to Prometheus."""
        if self._client is not None:
            return

        self._log.info("Connecting to Prometheus")

        # Build SSL context if needed
        ssl_context: Union[ssl.SSLContext, bool] = self.settings.tls_verify
        if self.settings.tls_ca_cert or self.settings.tls_client_cert:
            ssl_context = ssl.create_default_context()
            if self.settings.tls_ca_cert:
                ssl_context.load_verify_locations(cafile=str(self.settings.tls_ca_cert))
            if self.settings.tls_client_cert and self.settings.tls_client_key:
                ssl_context.load_cert_chain(
                    certfile=str(self.settings.tls_client_cert),
                    keyfile=str(self.settings.tls_client_key),
                )

        # Build client configuration
        client_kwargs: dict[str, Any] = {
            "base_url": self.settings.url,
            "timeout": httpx.Timeout(self.settings.timeout),
            "limits": httpx.Limits(
                max_connections=self.settings.max_connections,
                max_keepalive_connections=self.settings.max_connections // 2,
            ),
            "verify": ssl_context,
            "headers": {
                "Accept": "application/json",
                "User-Agent": "prometheus-mcp-server/1.0.0",
            },
        }

        # Add authentication headers
        client_kwargs["headers"].update(self.settings.get_auth_headers())

        # Add basic auth if configured
        basic_auth = self.settings.get_basic_auth()
        if basic_auth:
            client_kwargs["auth"] = basic_auth

        # Handle AWS SigV4 authentication
        self._aws_credentials: Any = None
        self._aws_region: Optional[str] = None
        self._aws_service: Optional[str] = None

        if self.settings.auth_type == AuthType.AWS_SIGV4:
            try:
                from botocore.session import Session

                session = Session()
                if self.settings.aws_profile:
                    session.set_config_variable("profile", self.settings.aws_profile)
                credentials = session.get_credentials()

                if credentials is None:
                    raise PrometheusConnectionError(
                        "AWS credentials not found. Configure credentials via "
                        "environment variables, AWS profile, or IAM role."
                    )

                # Store frozen credentials for request signing
                self._aws_credentials = credentials.get_frozen_credentials()
                self._aws_region = self.settings.aws_region
                self._aws_service = self.settings.aws_service
                self._log.info(
                    "AWS SigV4 authentication configured",
                    region=self._aws_region,
                    service=self._aws_service,
                )
            except ImportError:
                raise PrometheusConnectionError(
                    "AWS SigV4 authentication requires botocore. "
                    "Install with: pip install botocore"
                )

        self._client = httpx.AsyncClient(**client_kwargs)
        self._log.info("Connected to Prometheus")

    async def close(self) -> None:
        """Close the connection."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            self._log.info("Disconnected from Prometheus")

    def _sign_aws_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Optional[bytes] = None,
    ) -> dict[str, str]:
        """
        Sign request with AWS SigV4.

        Args:
            method: HTTP method
            url: Full URL
            headers: Request headers
            body: Request body

        Returns:
            Updated headers with AWS signature
        """
        if self._aws_credentials is None:
            return headers

        try:
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
            from botocore.credentials import Credentials

            # Create credentials object from frozen credentials
            credentials = Credentials(
                access_key=self._aws_credentials.access_key,
                secret_key=self._aws_credentials.secret_key,
                token=self._aws_credentials.token,
            )

            # Create AWS request
            aws_request = AWSRequest(
                method=method.upper(),
                url=url,
                headers=headers,
                data=body or b"",
            )

            # Sign the request
            SigV4Auth(credentials, self._aws_service, self._aws_region).add_auth(
                aws_request
            )

            # Return signed headers
            return dict(aws_request.headers)

        except Exception as e:
            self._log.error("Failed to sign AWS request", error=str(e))
            raise PrometheusConnectionError(f"AWS SigV4 signing failed: {e}") from e

    def _parse_time(self, time_str: Union[str, datetime, None]) -> Optional[str]:
        """
        Parse time string to Prometheus format.

        Supports:
        - Relative: "1h", "30m", "1d", "now"
        - Absolute: ISO 8601, Unix timestamp
        - datetime objects

        Args:
            time_str: Time specification

        Returns:
            Time in Prometheus format (Unix timestamp as string)
        """
        if time_str is None:
            return None

        if isinstance(time_str, datetime):
            return str(time_str.timestamp())

        time_str = str(time_str).strip().lower()

        # Handle "now"
        if time_str == "now":
            return str(datetime.now().timestamp())

        # Handle relative time (e.g., "1h", "30m", "1d")
        relative_units = {
            "s": timedelta(seconds=1),
            "m": timedelta(minutes=1),
            "h": timedelta(hours=1),
            "d": timedelta(days=1),
            "w": timedelta(weeks=1),
        }

        for unit, delta in relative_units.items():
            if time_str.endswith(unit):
                try:
                    value = int(time_str[:-1])
                    result_time = datetime.now() - (delta * value)
                    return str(result_time.timestamp())
                except ValueError:
                    pass

        # Try parsing as ISO 8601 or other formats
        try:
            parsed = date_parser.parse(time_str)
            return str(parsed.timestamp())
        except (ValueError, TypeError):
            pass

        # Try parsing as Unix timestamp
        try:
            float(time_str)
            return time_str
        except ValueError:
            pass

        raise PrometheusQueryError(f"Invalid time format: {time_str}")

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Make HTTP request to Prometheus API with retry logic.

        Args:
            method: HTTP method
            path: API path
            params: Query parameters
            data: Form data for POST requests

        Returns:
            API response data

        Raises:
            PrometheusAPIError: On API errors
            PrometheusConnectionError: On connection errors
            PrometheusTimeoutError: On timeout
        """
        if self._client is None:
            await self.connect()

        assert self._client is not None

        full_url = urljoin(self.settings.url, path)
        log = self._log.bind(method=method, path=path)

        # Prepare request headers and body for AWS SigV4 signing
        request_headers: dict[str, str] = {}
        request_body: Optional[bytes] = None

        if self._aws_credentials is not None:
            # For POST with form data, encode as URL-encoded form
            if data:
                from urllib.parse import urlencode
                # Handle list parameters (like match[])
                encoded_parts = []
                for key, value in data.items():
                    if isinstance(value, list):
                        for v in value:
                            encoded_parts.append(f"{key}={v}")
                    else:
                        encoded_parts.append(f"{key}={value}")
                request_body = "&".join(encoded_parts).encode("utf-8")
                request_headers["Content-Type"] = "application/x-www-form-urlencoded"

            # Build full URL with query params for signing
            if params:
                from urllib.parse import urlencode as url_encode
                param_parts = []
                for key, value in params.items():
                    if isinstance(value, list):
                        for v in value:
                            param_parts.append((key, v))
                    else:
                        param_parts.append((key, value))
                query_string = url_encode(param_parts)
                sign_url = f"{full_url}?{query_string}"
            else:
                sign_url = full_url

            # Sign the request
            request_headers = self._sign_aws_request(
                method=method,
                url=sign_url,
                headers=request_headers,
                body=request_body,
            )

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.settings.max_retries + 1),
                wait=wait_exponential(
                    multiplier=self.settings.retry_delay,
                    max=self.settings.retry_delay * (self.settings.retry_backoff ** 3),
                ),
                retry=retry_if_exception_type(
                    (httpx.TransportError, httpx.TimeoutException)
                ),
                reraise=True,
            ):
                with attempt:
                    attempt_num = attempt.retry_state.attempt_number
                    if attempt_num > 1:
                        log.warning("Retrying request", attempt=attempt_num)

                    # Use signed headers if available, otherwise use default
                    if self._aws_credentials is not None:
                        response = await self._client.request(
                            method=method,
                            url=path,
                            params=params,
                            content=request_body,
                            headers=request_headers,
                        )
                    else:
                        response = await self._client.request(
                            method=method,
                            url=path,
                            params=params,
                            data=data,
                        )

        except httpx.TimeoutException as e:
            log.error("Request timeout", error=str(e))
            raise PrometheusTimeoutError(f"Request timeout: {e}") from e
        except httpx.TransportError as e:
            log.error("Connection error", error=str(e))
            raise PrometheusConnectionError(f"Connection error: {e}") from e
        except RetryError as e:
            log.error("Max retries exceeded", error=str(e))
            raise PrometheusConnectionError(f"Max retries exceeded: {e}") from e

        # Handle HTTP errors
        if response.status_code >= 400:
            error_detail = response.text
            try:
                error_json = response.json()
                if "error" in error_json:
                    error_detail = error_json["error"]
            except Exception:
                pass

            log.error(
                "API error",
                status_code=response.status_code,
                error=error_detail,
            )

            if response.status_code == 400:
                raise PrometheusQueryError(f"Bad request: {error_detail}")
            elif response.status_code == 401:
                raise PrometheusAPIError(f"Authentication failed: {error_detail}")
            elif response.status_code == 403:
                raise PrometheusAPIError(f"Access denied: {error_detail}")
            elif response.status_code == 503:
                raise PrometheusAPIError(f"Service unavailable: {error_detail}")
            else:
                raise PrometheusAPIError(
                    f"HTTP {response.status_code}: {error_detail}"
                )

        # Parse response
        try:
            result = response.json()
        except Exception as e:
            log.error("Failed to parse response", error=str(e))
            raise PrometheusAPIError(f"Invalid JSON response: {e}") from e

        # Check Prometheus API status
        if result.get("status") == "error":
            error_type = result.get("errorType", "unknown")
            error_msg = result.get("error", "Unknown error")
            log.error("Prometheus error", error_type=error_type, error=error_msg)
            raise PrometheusQueryError(f"{error_type}: {error_msg}")

        return result

    # ==========================================================================
    # Query API
    # ==========================================================================

    async def query(
        self,
        promql: str,
        time: Optional[Union[str, datetime]] = None,
        timeout: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Execute instant PromQL query.

        Args:
            promql: PromQL query expression
            time: Evaluation timestamp (default: current time)
            timeout: Query timeout

        Returns:
            Query result with 'resultType' and 'result' fields

        Example:
            ```python
            result = await client.query("up")
            # result = {"resultType": "vector", "result": [...]}
            ```
        """
        params: dict[str, Any] = {"query": promql}

        if time:
            params["time"] = self._parse_time(time)
        if timeout:
            params["timeout"] = timeout

        self._log.debug("Executing instant query", query=promql)
        response = await self._request("POST", "/api/v1/query", data=params)
        return response.get("data", {})

    async def query_range(
        self,
        promql: str,
        start: Union[str, datetime],
        end: Union[str, datetime],
        step: Optional[str] = None,
        timeout: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Execute range PromQL query.

        Args:
            promql: PromQL query expression
            start: Start time
            end: End time
            step: Query resolution step (default from settings)
            timeout: Query timeout

        Returns:
            Query result with 'resultType' and 'result' fields

        Example:
            ```python
            result = await client.query_range(
                "rate(http_requests_total[5m])",
                start="1h",
                end="now",
                step="1m"
            )
            ```
        """
        params: dict[str, Any] = {
            "query": promql,
            "start": self._parse_time(start),
            "end": self._parse_time(end),
            "step": step or self.settings.default_step,
        }

        if timeout:
            params["timeout"] = timeout

        self._log.debug(
            "Executing range query",
            query=promql,
            start=params["start"],
            end=params["end"],
            step=params["step"],
        )
        response = await self._request("POST", "/api/v1/query_range", data=params)
        return response.get("data", {})

    async def query_exemplars(
        self,
        promql: str,
        start: Union[str, datetime],
        end: Union[str, datetime],
    ) -> list[dict[str, Any]]:
        """
        Query exemplars.

        Args:
            promql: PromQL query expression (selector)
            start: Start time
            end: End time

        Returns:
            List of exemplars
        """
        params: dict[str, Any] = {
            "query": promql,
            "start": self._parse_time(start),
            "end": self._parse_time(end),
        }

        response = await self._request("POST", "/api/v1/query_exemplars", data=params)
        return response.get("data", [])

    # ==========================================================================
    # Metadata API
    # ==========================================================================

    async def get_series(
        self,
        match: list[str],
        start: Optional[Union[str, datetime]] = None,
        end: Optional[Union[str, datetime]] = None,
    ) -> list[dict[str, str]]:
        """
        Find time series matching label matchers.

        Args:
            match: List of series selectors
            start: Start time
            end: End time

        Returns:
            List of matching series with their labels
        """
        params: dict[str, Any] = {"match[]": match}

        if start:
            params["start"] = self._parse_time(start)
        if end:
            params["end"] = self._parse_time(end)

        response = await self._request("POST", "/api/v1/series", data=params)
        return response.get("data", [])

    async def get_labels(
        self,
        match: Optional[list[str]] = None,
        start: Optional[Union[str, datetime]] = None,
        end: Optional[Union[str, datetime]] = None,
    ) -> list[str]:
        """
        Get all label names.

        Args:
            match: Optional series selectors to filter
            start: Start time
            end: End time

        Returns:
            List of label names
        """
        params: dict[str, Any] = {}

        if match:
            params["match[]"] = match
        if start:
            params["start"] = self._parse_time(start)
        if end:
            params["end"] = self._parse_time(end)

        response = await self._request("GET", "/api/v1/labels", params=params)
        return response.get("data", [])

    async def get_label_values(
        self,
        label: str,
        match: Optional[list[str]] = None,
        start: Optional[Union[str, datetime]] = None,
        end: Optional[Union[str, datetime]] = None,
    ) -> list[str]:
        """
        Get values for a specific label.

        Args:
            label: Label name
            match: Optional series selectors to filter
            start: Start time
            end: End time

        Returns:
            List of label values
        """
        params: dict[str, Any] = {}

        if match:
            params["match[]"] = match
        if start:
            params["start"] = self._parse_time(start)
        if end:
            params["end"] = self._parse_time(end)

        response = await self._request(
            "GET", f"/api/v1/label/{label}/values", params=params
        )
        return response.get("data", [])

    async def list_metrics(self) -> list[str]:
        """
        Get all metric names.

        Returns:
            List of metric names
        """
        return await self.get_label_values("__name__")

    async def get_metric_metadata(
        self,
        metric: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> dict[str, list[dict[str, str]]]:
        """
        Get metadata about metrics.

        Args:
            metric: Optional metric name filter
            limit: Maximum number of metrics to return

        Returns:
            Dict mapping metric names to their metadata
        """
        params: dict[str, Any] = {}

        if metric:
            params["metric"] = metric
        if limit:
            params["limit"] = limit

        response = await self._request("GET", "/api/v1/metadata", params=params)
        return response.get("data", {})

    # ==========================================================================
    # Targets API
    # ==========================================================================

    async def get_targets(
        self,
        state: Optional[str] = None,
        scrape_pool: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Get information about scrape targets.

        Args:
            state: Filter by target state ('active', 'dropped', 'any')
            scrape_pool: Filter by scrape pool name

        Returns:
            Dict with 'activeTargets' and 'droppedTargets'
        """
        params: dict[str, Any] = {}

        if state:
            params["state"] = state
        if scrape_pool:
            params["scrapePool"] = scrape_pool

        response = await self._request("GET", "/api/v1/targets", params=params)
        return response.get("data", {})

    async def get_target_metadata(
        self,
        match_target: Optional[str] = None,
        metric: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """
        Get metadata about target metrics.

        Args:
            match_target: Label selector to match targets
            metric: Metric name filter
            limit: Maximum number of results

        Returns:
            List of target metadata
        """
        params: dict[str, Any] = {}

        if match_target:
            params["match_target"] = match_target
        if metric:
            params["metric"] = metric
        if limit:
            params["limit"] = limit

        response = await self._request("GET", "/api/v1/targets/metadata", params=params)
        return response.get("data", [])

    # ==========================================================================
    # Rules API
    # ==========================================================================

    async def get_rules(
        self,
        rule_type: Optional[str] = None,
        rule_name: Optional[list[str]] = None,
        rule_group: Optional[list[str]] = None,
        file: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """
        Get alerting and recording rules.

        Args:
            rule_type: Filter by type ('alert' or 'record')
            rule_name: Filter by rule names
            rule_group: Filter by rule group names
            file: Filter by rule file names

        Returns:
            Dict with 'groups' containing rules
        """
        params: dict[str, Any] = {}

        if rule_type:
            params["type"] = rule_type
        if rule_name:
            params["rule_name[]"] = rule_name
        if rule_group:
            params["rule_group[]"] = rule_group
        if file:
            params["file[]"] = file

        response = await self._request("GET", "/api/v1/rules", params=params)
        return response.get("data", {})

    # ==========================================================================
    # Alerts API
    # ==========================================================================

    async def get_alerts(self) -> list[dict[str, Any]]:
        """
        Get active alerts.

        Returns:
            List of active alerts
        """
        response = await self._request("GET", "/api/v1/alerts")
        return response.get("data", {}).get("alerts", [])

    # ==========================================================================
    # Status API
    # ==========================================================================

    async def get_config(self) -> str:
        """
        Get current Prometheus configuration.

        Returns:
            YAML configuration string
        """
        response = await self._request("GET", "/api/v1/status/config")
        return response.get("data", {}).get("yaml", "")

    async def get_flags(self) -> dict[str, str]:
        """
        Get Prometheus command-line flags.

        Returns:
            Dict of flag names to values
        """
        response = await self._request("GET", "/api/v1/status/flags")
        return response.get("data", {})

    async def get_runtime_info(self) -> dict[str, Any]:
        """
        Get Prometheus runtime information.

        Returns:
            Runtime information including version, storage, etc.
        """
        response = await self._request("GET", "/api/v1/status/runtimeinfo")
        return response.get("data", {})

    async def get_build_info(self) -> dict[str, str]:
        """
        Get Prometheus build information.

        Returns:
            Build information including version, goVersion, etc.
        """
        response = await self._request("GET", "/api/v1/status/buildinfo")
        return response.get("data", {})

    async def get_tsdb_status(self) -> dict[str, Any]:
        """
        Get TSDB cardinality statistics.

        Returns:
            TSDB status including series count, chunk count, etc.
        """
        response = await self._request("GET", "/api/v1/status/tsdb")
        return response.get("data", {})

    async def get_wal_replay_status(self) -> dict[str, Any]:
        """
        Get WAL replay status.

        Returns:
            WAL replay status
        """
        response = await self._request("GET", "/api/v1/status/walreplay")
        return response.get("data", {})

    # ==========================================================================
    # Health checks
    # ==========================================================================

    async def is_healthy(self) -> bool:
        """
        Check if Prometheus is healthy.

        Returns:
            True if healthy, False otherwise
        """
        try:
            if self._client is None:
                await self.connect()
            assert self._client is not None
            response = await self._client.get("/-/healthy")
            return response.status_code == 200
        except Exception as e:
            self._log.warning("Health check failed", error=str(e))
            return False

    async def is_ready(self) -> bool:
        """
        Check if Prometheus is ready to serve traffic.

        Returns:
            True if ready, False otherwise
        """
        try:
            if self._client is None:
                await self.connect()
            assert self._client is not None
            response = await self._client.get("/-/ready")
            return response.status_code == 200
        except Exception as e:
            self._log.warning("Readiness check failed", error=str(e))
            return False

    async def health_check(self) -> bool:
        """Alias for is_healthy."""
        return await self.is_healthy()

    async def ready_check(self) -> bool:
        """Alias for is_ready."""
        return await self.is_ready()

    async def get_status(self, status_type: str = "buildinfo") -> dict[str, Any]:
        """
        Get Prometheus status information.

        Args:
            status_type: Type of status (config, flags, runtimeinfo, buildinfo, tsdb, walreplay)

        Returns:
            Status information
        """
        status_methods = {
            "config": self.get_config,
            "flags": self.get_flags,
            "runtimeinfo": self.get_runtime_info,
            "buildinfo": self.get_build_info,
            "tsdb": self.get_tsdb_status,
            "walreplay": self.get_wal_replay_status,
        }

        method = status_methods.get(status_type)
        if method is None:
            raise PrometheusQueryError(f"Invalid status type: {status_type}")

        result = await method()
        # Wrap string results (config returns YAML string)
        if isinstance(result, str):
            return {"yaml": result}
        return result

    # ==========================================================================
    # Series API (additional methods)
    # ==========================================================================

    async def series(
        self,
        match: list[str],
        start: Optional[Union[str, datetime]] = None,
        end: Optional[Union[str, datetime]] = None,
        limit: Optional[int] = None,
    ) -> list[dict[str, str]]:
        """
        Find time series matching label matchers.

        Args:
            match: List of series selectors
            start: Start time
            end: End time
            limit: Maximum number of series to return

        Returns:
            List of matching series with their labels
        """
        results = await self.get_series(match=match, start=start, end=end)
        if limit:
            results = results[:limit]
        return results

    async def get_label_names(
        self,
        start: Optional[Union[str, datetime]] = None,
        end: Optional[Union[str, datetime]] = None,
        match: Optional[list[str]] = None,
    ) -> list[str]:
        """
        Get all label names.

        Args:
            start: Start time
            end: End time
            match: Optional series selectors to filter

        Returns:
            List of label names
        """
        return await self.get_labels(match=match, start=start, end=end)

    # ==========================================================================
    # Admin API (dangerous operations)
    # ==========================================================================

    async def delete_series(
        self,
        match: list[str],
        start: Optional[Union[str, datetime]] = None,
        end: Optional[Union[str, datetime]] = None,
    ) -> None:
        """
        Delete time series matching selectors.

        ⚠️ DANGEROUS: This permanently deletes data.

        Args:
            match: Series selectors to match for deletion
            start: Start time for deletion range
            end: End time for deletion range
        """
        params: dict[str, Any] = {"match[]": match}

        if start:
            params["start"] = self._parse_time(start)
        if end:
            params["end"] = self._parse_time(end)

        self._log.warning("Deleting series", match=match, start=start, end=end)
        await self._request("POST", "/api/v1/admin/tsdb/delete_series", data=params)

    async def clean_tombstones(self) -> None:
        """
        Remove deleted data from disk.

        ⚠️ DANGEROUS: Run after delete_series to reclaim disk space.
        """
        self._log.warning("Cleaning tombstones")
        await self._request("POST", "/api/v1/admin/tsdb/clean_tombstones")

    async def snapshot(self, skip_head: bool = False) -> dict[str, str]:
        """
        Create TSDB snapshot.

        Args:
            skip_head: Skip data in the head block

        Returns:
            Dict with snapshot name
        """
        params: dict[str, Any] = {}
        if skip_head:
            params["skip_head"] = "true"

        self._log.info("Creating snapshot", skip_head=skip_head)
        response = await self._request("POST", "/api/v1/admin/tsdb/snapshot", params=params)
        return response.get("data", {})

    async def reload_config(self) -> bool:
        """
        Trigger Prometheus config reload.

        ⚠️ DANGEROUS: Reloads the configuration.

        Returns:
            True if successful
        """
        self._log.warning("Reloading Prometheus configuration")
        if self._client is None:
            await self.connect()
        assert self._client is not None
        response = await self._client.post("/-/reload")
        return response.status_code == 200

    async def get_alertmanagers(self) -> dict[str, Any]:
        """
        Get Alertmanager discovery information.

        Returns:
            Dict with active and dropped Alertmanagers
        """
        response = await self._request("GET", "/api/v1/alertmanagers")
        return response.get("data", {})


class AlertmanagerClient:
    """
    Async Alertmanager HTTP API client.
    """

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._log = logger.bind(alertmanager_url=url)

    async def connect(self) -> None:
        """Establish connection to Alertmanager."""
        if self._client is not None:
            return
        self._client = httpx.AsyncClient(
            base_url=self.url,
            timeout=httpx.Timeout(self.timeout),
            headers={"Accept": "application/json"},
        )
        self._log.info("Connected to Alertmanager")

    async def close(self) -> None:
        """Close the connection."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict[str, Any]] = None,
        json_data: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Make HTTP request to Alertmanager API."""
        if self._client is None:
            await self.connect()
        assert self._client is not None

        response = await self._client.request(
            method=method,
            url=path,
            params=params,
            json=json_data,
        )

        if response.status_code >= 400:
            raise PrometheusAPIError(f"Alertmanager error: {response.text}")

        if response.status_code == 204:
            return {}
        return response.json()

    async def get_alerts(
        self,
        active: bool = True,
        silenced: bool = True,
        inhibited: bool = True,
        unprocessed: bool = True,
        filter_: Optional[list[str]] = None,
        receiver: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Get alerts from Alertmanager."""
        params: dict[str, Any] = {
            "active": str(active).lower(),
            "silenced": str(silenced).lower(),
            "inhibited": str(inhibited).lower(),
            "unprocessed": str(unprocessed).lower(),
        }
        if filter_:
            params["filter"] = filter_
        if receiver:
            params["receiver"] = receiver

        return await self._request("GET", "/api/v2/alerts", params=params)

    async def get_silences(
        self,
        filter_: Optional[list[str]] = None,
    ) -> list[dict[str, Any]]:
        """Get all silences."""
        params: dict[str, Any] = {}
        if filter_:
            params["filter"] = filter_
        return await self._request("GET", "/api/v2/silences", params=params)

    async def create_silence(
        self,
        matchers: list[dict[str, Any]],
        starts_at: str,
        ends_at: str,
        created_by: str,
        comment: str,
    ) -> dict[str, str]:
        """Create a new silence."""
        data = {
            "matchers": matchers,
            "startsAt": starts_at,
            "endsAt": ends_at,
            "createdBy": created_by,
            "comment": comment,
        }
        return await self._request("POST", "/api/v2/silences", json_data=data)

    async def delete_silence(self, silence_id: str) -> None:
        """Delete a silence by ID."""
        await self._request("DELETE", f"/api/v2/silence/{silence_id}")

    async def get_status(self) -> dict[str, Any]:
        """Get Alertmanager status."""
        return await self._request("GET", "/api/v2/status")

    async def get_receivers(self) -> list[dict[str, Any]]:
        """Get all receivers."""
        return await self._request("GET", "/api/v2/receivers")
