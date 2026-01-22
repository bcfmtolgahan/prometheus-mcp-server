# Contributing to Prometheus MCP Server

First off, thank you for considering contributing to Prometheus MCP Server! It's people like you that make this project better.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps which reproduce the problem**
- **Provide specific examples to demonstrate the steps**
- **Describe the behavior you observed after following the steps**
- **Explain which behavior you expected to see instead and why**
- **Include logs if applicable**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Use a clear and descriptive title**
- **Provide a step-by-step description of the suggested enhancement**
- **Provide specific examples to demonstrate the steps**
- **Describe the current behavior and explain the behavior you expected to see instead**
- **Explain why this enhancement would be useful**

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code lints
6. Issue that pull request!

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Docker (for containerized testing)
- Prometheus instance for integration testing

### Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/prometheus-mcp-server.git
cd prometheus-mcp-server

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/prometheus_mcp_server --cov-report=html

# Run specific test file
pytest tests/test_client.py

# Run specific test
pytest tests/test_client.py::TestPrometheusClient::test_query
```

### Code Style

We use the following tools for code style and quality:

- **Ruff**: Linting and formatting
- **mypy**: Static type checking

```bash
# Format code
ruff format .

# Check linting
ruff check .

# Run type checker
mypy src/
```

### Commit Messages

We follow conventional commits specification:

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Changes that do not affect the meaning of the code
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `perf`: A code change that improves performance
- `test`: Adding missing tests or correcting existing tests
- `chore`: Changes to the build process or auxiliary tools

Example:
```
feat: add support for AWS SigV4 authentication

- Implement SigV4 signing for Amazon Managed Prometheus
- Add aws_region and aws_profile configuration options
- Update documentation with AMP examples
```

### Documentation

- Update README.md for user-facing changes
- Add docstrings to all public functions and classes
- Update CHANGELOG.md for notable changes

## Project Structure

```
prometheus-mcp-server/
├── src/prometheus_mcp_server/
│   ├── __init__.py      # Package exports
│   ├── server.py        # MCP server implementation
│   ├── client.py        # Prometheus HTTP client
│   ├── config.py        # Configuration management
│   ├── cli.py           # Command-line interface
│   └── exceptions.py    # Custom exceptions
├── tests/
│   ├── conftest.py      # Test fixtures
│   ├── test_client.py   # Client tests
│   ├── test_config.py   # Config tests
│   └── test_server.py   # Server tests
├── deploy/
│   ├── kubernetes/      # K8s manifests
│   └── helm/            # Helm chart
└── .github/
    └── workflows/       # CI/CD pipelines
```

## Adding New Tools

To add a new MCP tool:

1. Add the tool definition in `server.py` within `list_tools()`
2. Implement the tool handler in `_execute_tool()`
3. Add corresponding client method if needed in `client.py`
4. Write tests for the new tool
5. Update README.md with the new tool documentation

Example:
```python
# In list_tools()
Tool(
    name="prometheus_new_tool",
    description="Description of what the tool does",
    inputSchema={
        "type": "object",
        "properties": {
            "param1": {
                "type": "string",
                "description": "Parameter description",
            },
        },
        "required": ["param1"],
    },
),

# In _execute_tool()
elif name == "prometheus_new_tool":
    result = await self.client.new_method(
        param1=arguments["param1"],
    )
    return {"result": result}
```

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create a pull request with the changes
4. After merge, create a git tag: `git tag v1.0.1`
5. Push the tag: `git push origin v1.0.1`
6. GitHub Actions will automatically create a release

## Questions?

Feel free to open an issue with your question or reach out to the maintainers.

Thank you for contributing!
