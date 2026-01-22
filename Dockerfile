# Prometheus MCP Server
# Multi-stage build for minimal production image

# =============================================================================
# Build stage
# =============================================================================
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# =============================================================================
# Production stage
# =============================================================================
FROM python:3.12-slim as production

# Security: Run as non-root user
RUN groupadd -r prometheus && useradd -r -g prometheus prometheus

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY src/ ./src/

# Set Python path
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check - MCP streamable-http endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/mcp', timeout=5)" || exit 1

# Switch to non-root user
USER prometheus

# Default port for streamable-http transport (MCP standard: 8000)
EXPOSE 8000

# Default environment variables
ENV PROMETHEUS_MCP_TRANSPORT=http
ENV PROMETHEUS_MCP_HOST=0.0.0.0
ENV PROMETHEUS_MCP_PORT=8000
ENV PROMETHEUS_MCP_LOG_LEVEL=INFO
ENV PROMETHEUS_MCP_LOG_FORMAT=json

# Entry point
ENTRYPOINT ["prometheus-mcp-server"]
CMD ["--transport", "http"]
