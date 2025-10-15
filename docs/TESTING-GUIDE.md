# Testing Guide - Offensive Security Toolkit

Comprehensive guide for testing the offensive security toolkit.

**Version**: 0.1.0
**Last Updated**: 2025-10-15

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Writing Tests](#writing-tests)
- [CI/CD Integration](#cicd-integration)
- [Code Coverage](#code-coverage)
- [Best Practices](#best-practices)

---

## Overview

### Testing Philosophy

This toolkit follows a comprehensive testing strategy:

1. **Unit Tests**: Test individual functions and classes in isolation
2. **Integration Tests**: Test module interactions and workflows
3. **Security Tests**: Verify authorization and validation mechanisms
4. **Performance Tests**: Ensure tools meet performance requirements

### Test Coverage Goals

- **Unit Tests**: 80% minimum coverage
- **Critical Functions**: 100% coverage (authorization, validation, security)
- **Integration Tests**: All major workflows tested
- **Security Tests**: All security features validated

---

## Test Structure

### Directory Layout

```
tests/
├── __init__.py
├── conftest.py              # Shared fixtures and configuration
├── unit/                    # Unit tests
│   ├── __init__.py
│   ├── test_logger.py
│   ├── test_config.py
│   ├── test_helpers.py
│   └── test_port_scanner.py
├── integration/             # Integration tests
│   ├── __init__.py
│   └── test_workflows.py
└── fixtures/                # Test data and fixtures
    └── test_targets.txt
```

### Test File Naming

- Test files: `test_<module_name>.py`
- Test classes: `Test<ClassName>`
- Test functions: `test_<function_name>`

---

## Running Tests

### Prerequisites

Install development dependencies:

```bash
pip install -r requirements-dev.txt
```

### Basic Test Execution

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/unit/test_logger.py

# Run specific test class
pytest tests/unit/test_logger.py::TestSetupLogger

# Run specific test function
pytest tests/unit/test_logger.py::TestSetupLogger::test_logger_creation
```

### Test with Coverage

```bash
# Run tests with coverage report
pytest --cov=. --cov-report=html

# View coverage in terminal
pytest --cov=. --cov-report=term-missing

# Generate XML coverage for CI
pytest --cov=. --cov-report=xml
```

### Test Filtering

```bash
# Run tests by keyword
pytest -k "test_logger"

# Run tests by marker
pytest -m "slow"

# Skip certain tests
pytest --ignore=tests/integration/
```

### Parallel Testing

```bash
# Install pytest-xdist
pip install pytest-xdist

# Run tests in parallel
pytest -n auto
```

---

## Writing Tests

### Basic Test Structure

```python
"""
Unit tests for module_name.py
"""

import pytest
from module_name import function_to_test


class TestFunctionName:
    """Tests for function_to_test."""

    def test_basic_functionality(self):
        """Test basic function behavior."""
        result = function_to_test("input")
        assert result == "expected_output"

    def test_edge_case(self):
        """Test edge case handling."""
        result = function_to_test("")
        assert result is None

    def test_error_handling(self):
        """Test error handling."""
        with pytest.raises(ValueError):
            function_to_test(invalid_input)
```

### Using Fixtures

```python
@pytest.fixture
def sample_data():
    """Provide sample test data."""
    return {"key": "value"}


def test_with_fixture(sample_data):
    """Test using fixture."""
    assert sample_data["key"] == "value"
```

### Mocking and Patching

```python
from unittest.mock import Mock, patch


def test_with_mock(monkeypatch):
    """Test with mocked dependencies."""
    mock_socket = Mock()
    mock_socket.connect_ex.return_value = 0

    monkeypatch.setattr("socket.socket", lambda *args: mock_socket)

    # Test code using mocked socket
    result = scan_port("127.0.0.1", 80)
    assert result is True
```

### Parametrized Tests

```python
@pytest.mark.parametrize("input,expected", [
    ("192.168.1.1", True),
    ("example.com", True),
    ("invalid", False),
])
def test_validate_target(input, expected):
    """Test target validation with multiple inputs."""
    assert validate_target(input) == expected
```

### Testing Async Code

```python
import pytest


@pytest.mark.asyncio
async def test_async_function():
    """Test asynchronous function."""
    result = await async_scan_port("127.0.0.1", 80)
    assert result is not None
```

---

## CI/CD Integration

### GitHub Actions Workflow

The CI/CD pipeline runs automatically on:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`

### Workflow Stages

1. **Test Suite**: Run tests on multiple OS and Python versions
2. **Security Scan**: Bandit security scanning
3. **Code Quality**: Black, isort, pylint checks
4. **Build**: Package building and artifact upload

### Local CI Simulation

```bash
# Run all CI checks locally
./scripts/run_ci_checks.sh

# Or manually:
pytest
black --check .
flake8 .
bandit -r .
mypy .
```

### Pre-commit Hooks

Install pre-commit hooks to run checks before commits:

```bash
# Install hooks
pre-commit install

# Run hooks manually
pre-commit run --all-files

# Update hook versions
pre-commit autoupdate
```

---

## Code Coverage

### Viewing Coverage Reports

```bash
# Generate HTML report
pytest --cov=. --cov-report=html

# Open report in browser
open htmlcov/index.html  # Mac/Linux
start htmlcov/index.html  # Windows
```

### Coverage Configuration

Configured in `pytest.ini`:

```ini
[coverage:run]
source = .
omit =
    */tests/*
    */venv/*
    */__pycache__/*

[coverage:report]
precision = 2
show_missing = True
```

### Improving Coverage

1. **Identify uncovered code**:
   ```bash
   pytest --cov=. --cov-report=term-missing
   ```

2. **Add tests for uncovered lines**

3. **Verify improvement**:
   ```bash
   pytest --cov=. --cov-report=term
   ```

---

## Best Practices

### Test Organization

1. **One test file per module**: `test_logger.py` for `logger.py`
2. **Group related tests**: Use test classes to group related tests
3. **Clear test names**: Test names should describe what they test
4. **Independent tests**: Each test should be independent and isolated

### Test Data

1. **Use fixtures**: Share test data with pytest fixtures
2. **Avoid hardcoding**: Use constants or configuration
3. **Test fixtures**: Store test data in `tests/fixtures/`
4. **Clean up**: Use fixtures to clean up test data after tests

### Assertions

```python
# Good assertions
assert result == expected
assert result is True
assert "error" in response

# With messages
assert result == expected, f"Expected {expected}, got {result}"

# Multiple assertions
assert result is not None
assert len(result) == 5
assert all(item > 0 for item in result)
```

### Error Testing

```python
# Test exceptions
with pytest.raises(ValueError) as exc_info:
    dangerous_function()

assert "expected error message" in str(exc_info.value)

# Test warnings
with pytest.warns(UserWarning):
    function_that_warns()
```

### Mocking Best Practices

1. **Mock external dependencies**: Network calls, file I/O, external APIs
2. **Don't over-mock**: Test real code where possible
3. **Use appropriate mocking level**: Mock at the right abstraction level
4. **Verify mock calls**: Assert mocks were called correctly

### Security Testing

1. **Test authorization checks**:
   ```python
   def test_unauthorized_access(self):
       """Test unauthorized access is denied."""
       result = check_authorization("unauthorized_target")
       assert result is False
   ```

2. **Test input validation**:
   ```python
   def test_sql_injection_prevention(self):
       """Test SQL injection is prevented."""
       malicious_input = "'; DROP TABLE users; --"
       with pytest.raises(ValidationError):
           process_input(malicious_input)
   ```

3. **Test rate limiting**:
   ```python
   def test_rate_limiting(self):
       """Test rate limiting is enforced."""
       limiter = RateLimiter(10)
       start = time.time()
       for _ in range(20):
           limiter.wait()
       elapsed = time.time() - start
       assert elapsed >= 1.8  # Should take at least 1.8s for 20 at 10/s
   ```

---

## Troubleshooting

### Common Issues

**Issue**: Tests fail with import errors
**Solution**:
```bash
# Ensure you're in the project root
cd offensive-toolkit

# Install in editable mode
pip install -e .
```

**Issue**: Coverage report shows 0%
**Solution**:
```bash
# Ensure coverage is tracking the right source
pytest --cov=. --cov-report=term-missing
```

**Issue**: Tests pass locally but fail in CI
**Solution**:
- Check Python version compatibility
- Verify all dependencies are in `requirements.txt`
- Check for platform-specific code

### Debugging Tests

```bash
# Run with debugging
pytest --pdb

# Run with print statements
pytest -s

# Run specific test with detailed output
pytest -vv tests/unit/test_logger.py::test_specific_function
```

---

## Examples

### Example 1: Testing a Network Tool

```python
class TestPortScanner:
    """Tests for PortScanner class."""

    def test_scan_open_port(self, mock_socket):
        """Test scanning an open port."""
        scanner = PortScanner()
        port, is_open, service = scanner.scan_port("127.0.0.1", 80)

        assert port == 80
        assert is_open is True
        assert service == "HTTP"

    def test_scan_closed_port(self, mock_socket):
        """Test scanning a closed port."""
        scanner = PortScanner()
        port, is_open, service = scanner.scan_port("127.0.0.1", 9999)

        assert port == 9999
        assert is_open is False
```

### Example 2: Testing Configuration Loading

```python
def test_load_config_with_overrides(temp_dir, monkeypatch):
    """Test configuration loading with environment overrides."""
    # Create config file
    config_file = temp_dir / "config.yaml"
    config_file.write_text("rate_limit:\n  requests_per_second: 10\n")

    # Set environment override
    monkeypatch.setenv("OSTK_RATE_LIMIT__REQUESTS_PER_SECOND", "20")

    # Load config
    config = load_config(str(config_file))

    # Environment should override file
    assert config["rate_limit"]["requests_per_second"] == 20
```

---

## Additional Resources

- [pytest Documentation](https://docs.pytest.org/)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [Python Testing Best Practices](https://docs.python-guide.org/writing/tests/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)

---

**Happy Testing!**

For questions or issues, open a GitHub issue or consult the [CONTRIBUTING.md](../CONTRIBUTING.md) guide.
