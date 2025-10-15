"""
Pytest configuration and shared fixtures.

This file contains fixtures and configuration used across all tests.
"""

import pytest
import tempfile
import shutil
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp)


@pytest.fixture
def test_config():
    """Provide a test configuration dictionary."""
    return {
        "logging": {
            "level": "DEBUG",
            "file": "logs/test.log",
            "format": "[%(asctime)s] [%(levelname)s] %(message)s"
        },
        "rate_limit": {
            "enabled": True,
            "requests_per_second": 100  # High for testing
        },
        "timeouts": {
            "connection": 5,
            "read": 10
        },
        "output": {
            "directory": "test_output",
            "format": "json"
        },
        "authorization": {
            "require_confirmation": False,  # Disable for testing
            "scope_file": "tests/fixtures/test_targets.txt"
        },
        "user_agent": "Offensive-Security-Toolkit-Test/0.1.0"
    }


@pytest.fixture
def authorized_targets_file(temp_dir):
    """Create a temporary authorized targets file."""
    targets_file = temp_dir / "authorized_targets.txt"
    targets_content = """# Test authorized targets
192.168.1.0/24
10.0.0.0/8
testlab.example.com
*.test.local
"""
    targets_file.write_text(targets_content)
    return str(targets_file)


@pytest.fixture
def mock_config_file(temp_dir, test_config):
    """Create a temporary config file for testing."""
    import yaml

    config_file = temp_dir / "test_config.yaml"
    with open(config_file, "w") as f:
        yaml.dump(test_config, f)

    return str(config_file)


@pytest.fixture
def sample_port_scan_results():
    """Provide sample port scan results for testing."""
    return {
        "target": "192.168.1.10",
        "total_ports_scanned": 16,
        "open_ports": 3,
        "results": {
            22: {"status": "open", "service": "SSH"},
            80: {"status": "open", "service": "HTTP"},
            443: {"status": "open", "service": "HTTPS"}
        }
    }


@pytest.fixture(autouse=True)
def cleanup_logs():
    """Clean up log files after each test."""
    yield
    # Cleanup happens after test
    log_files = Path("logs").glob("*.log")
    for log_file in log_files:
        if log_file.name.startswith("test_"):
            try:
                log_file.unlink()
            except (FileNotFoundError, PermissionError):
                pass


@pytest.fixture
def mock_socket(monkeypatch):
    """Mock socket connections for testing network tools."""
    class MockSocket:
        def __init__(self, *args, **kwargs):
            self.timeout = None

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect_ex(self, address):
            host, port = address
            # Simulate open ports for testing
            if port in [22, 80, 443]:
                return 0  # Success
            return 1  # Connection refused

        def close(self):
            pass

    import socket
    monkeypatch.setattr(socket, "socket", MockSocket)
    return MockSocket
