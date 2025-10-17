# Test Suite

Comprehensive test suite for the Offensive Security Toolkit.

## Structure

```
tests/
├── README.md           # This file
├── conftest.py         # Pytest configuration and fixtures
├── unit/               # Unit tests for individual modules
│   ├── test_*.py       # Unit test files
│   └── __init__.py
└── integration/        # Integration tests for workflows
    ├── test_*.py       # Integration test files
    └── __init__.py
```

## Running Tests

### Run All Tests
```bash
pytest
```

### Run with Coverage
```bash
pytest --cov=. --cov-report=html --cov-report=term
```

### Run Specific Test File
```bash
pytest tests/unit/test_port_scanner.py
```

### Run Specific Test Function
```bash
pytest tests/unit/test_port_scanner.py::test_port_scanner_basic
```

### Run with Verbose Output
```bash
pytest -v
```

### Run Integration Tests Only
```bash
pytest tests/integration/
```

### Run Unit Tests Only
```bash
pytest tests/unit/
```

## Test Categories

### Unit Tests
- Test individual functions and classes in isolation
- Mock external dependencies (network calls, file I/O)
- Fast execution (< 1 second per test)
- Located in `tests/unit/`

### Integration Tests
- Test complete workflows and tool interactions
- May use real network calls (to test targets only)
- Slower execution (may take several seconds)
- Located in `tests/integration/`

## Writing Tests

### Unit Test Example
```python
import pytest
from reconnaissance.port_scanner import PortScanner

def test_port_scanner_initialization():
    scanner = PortScanner(target="127.0.0.1")
    assert scanner.target == "127.0.0.1"

@pytest.mark.parametrize("port,expected", [
    (80, "HTTP"),
    (443, "HTTPS"),
    (22, "SSH"),
])
def test_service_detection(port, expected):
    # Test logic here
    pass
```

### Integration Test Example
```python
import pytest
from reconnaissance import dns_resolver, port_scanner

@pytest.mark.integration
def test_reconnaissance_workflow():
    # Test complete workflow
    pass
```

## Test Coverage Goals

- **Minimum**: 80% code coverage
- **Target**: 90% code coverage
- **Critical paths**: 100% coverage

## Mocking Network Calls

Use `pytest-mock` or `unittest.mock` for network operations:

```python
def test_with_mock(mocker):
    mock_response = mocker.patch('requests.get')
    mock_response.return_value.status_code = 200
    # Test logic here
```

## Fixtures

Common fixtures are defined in `conftest.py`:
- `authorized_target`: Provides a safe test target
- `temp_output_dir`: Temporary directory for test output
- `mock_config`: Mock configuration for testing

## CI/CD Integration

Tests run automatically on:
- Pull requests
- Push to main branch
- Nightly builds

## Test Data

Test data and fixtures should:
- Never contain real credentials
- Use example.com, test domains, or localhost
- Be clearly marked as test data
- Be gitignored if sensitive
