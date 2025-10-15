"""
Unit tests for reconnaissance/port_scanner.py module.
"""

import pytest
from unittest.mock import Mock, patch
from reconnaissance.port_scanner import PortScanner, COMMON_PORTS


class TestPortScanner:
    """Tests for PortScanner class."""

    def test_initialization(self, test_config):
        """Test PortScanner initialization."""
        scanner = PortScanner(test_config)

        assert scanner is not None
        assert scanner.config == test_config
        assert scanner.rate_limiter is not None

    def test_initialization_default_config(self):
        """Test PortScanner initialization with default config."""
        scanner = PortScanner()

        assert scanner is not None
        assert scanner.config is not None

    def test_scan_port_open(self, test_config, mock_socket):
        """Test scanning an open port."""
        scanner = PortScanner(test_config)
        port, is_open, service = scanner.scan_port("127.0.0.1", 22)

        assert port == 22
        assert is_open is True
        assert service == "SSH"

    def test_scan_port_closed(self, test_config, mock_socket):
        """Test scanning a closed port."""
        scanner = PortScanner(test_config)
        port, is_open, service = scanner.scan_port("127.0.0.1", 9999)

        assert port == 9999
        assert is_open is False

    def test_scan_port_timeout(self, test_config):
        """Test scanning with timeout."""
        scanner = PortScanner(test_config)

        # Mock socket that times out
        with patch("socket.socket") as mock_sock:
            mock_instance = Mock()
            mock_instance.connect_ex.side_effect = OSError("Timeout")
            mock_sock.return_value = mock_instance

            port, is_open, service = scanner.scan_port("127.0.0.1", 80, timeout=0.1)

            assert is_open is False

    def test_scan_ports_multiple(self, test_config, mock_socket):
        """Test scanning multiple ports."""
        scanner = PortScanner(test_config)
        ports = [22, 80, 443]

        results = scanner.scan_ports("127.0.0.1", ports)

        assert len(results) == 3
        assert 22 in results
        assert 80 in results
        assert 443 in results

    def test_parse_port_range_common(self, test_config):
        """Test parsing 'common' port range."""
        scanner = PortScanner(test_config)
        ports = scanner._parse_port_range("common")

        assert len(ports) > 0
        assert 22 in ports
        assert 80 in ports
        assert 443 in ports

    def test_parse_port_range_numeric(self, test_config):
        """Test parsing numeric range."""
        scanner = PortScanner(test_config)
        ports = scanner._parse_port_range("1-100")

        assert len(ports) == 100
        assert 1 in ports
        assert 100 in ports

    def test_parse_port_range_list(self, test_config):
        """Test parsing port list."""
        scanner = PortScanner(test_config)
        ports = scanner._parse_port_range("80,443,8080")

        assert len(ports) == 3
        assert 80 in ports
        assert 443 in ports
        assert 8080 in ports

    def test_parse_port_range_single(self, test_config):
        """Test parsing single port."""
        scanner = PortScanner(test_config)
        ports = scanner._parse_port_range("443")

        assert len(ports) == 1
        assert 443 in ports

    def test_parse_port_range_invalid(self, test_config):
        """Test parsing invalid port range."""
        scanner = PortScanner(test_config)
        ports = scanner._parse_port_range("invalid")

        assert len(ports) == 0

    def test_run_unauthorized_target(self, test_config):
        """Test running scan on unauthorized target."""
        test_config["authorization"]["require_confirmation"] = False
        scanner = PortScanner(test_config)

        # Target not in authorized list
        result = scanner.run("192.168.99.99", "common")

        assert "error" in result
        assert result["error"] == "Not authorized"

    def test_run_invalid_target(self, test_config, authorized_targets_file):
        """Test running scan on invalid target."""
        test_config["authorization"]["scope_file"] = authorized_targets_file
        test_config["authorization"]["require_confirmation"] = False
        scanner = PortScanner(test_config)

        result = scanner.run("invalid!@#target", "common")

        assert "error" in result
        assert result["error"] == "Invalid target"

    def test_run_successful_scan(self, test_config, authorized_targets_file, mock_socket):
        """Test successful port scan."""
        test_config["authorization"]["scope_file"] = authorized_targets_file
        test_config["authorization"]["require_confirmation"] = False
        scanner = PortScanner(test_config)

        result = scanner.run("192.168.1.10", "80,443")

        assert "target" in result
        assert result["target"] == "192.168.1.10"
        assert "total_ports_scanned" in result
        assert "open_ports" in result
        assert "results" in result

    def test_save_results(self, test_config, tmp_path, sample_port_scan_results):
        """Test saving scan results to file."""
        import json

        test_config["output"]["directory"] = str(tmp_path)
        scanner = PortScanner(test_config)
        scanner._save_results(sample_port_scan_results)

        # Check file was created
        output_files = list(tmp_path.glob("portscan_*.json"))
        assert len(output_files) == 1

        # Verify content
        with open(output_files[0]) as f:
            saved_results = json.load(f)

        assert saved_results["target"] == sample_port_scan_results["target"]
        assert saved_results["open_ports"] == sample_port_scan_results["open_ports"]


class TestCommonPorts:
    """Tests for COMMON_PORTS dictionary."""

    def test_common_ports_exist(self):
        """Test common ports are defined."""
        assert len(COMMON_PORTS) > 0
        assert 22 in COMMON_PORTS
        assert 80 in COMMON_PORTS
        assert 443 in COMMON_PORTS

    def test_common_ports_services(self):
        """Test common ports have service names."""
        assert COMMON_PORTS[22] == "SSH"
        assert COMMON_PORTS[80] == "HTTP"
        assert COMMON_PORTS[443] == "HTTPS"
        assert COMMON_PORTS[3389] == "RDP"


class TestPortScannerIntegration:
    """Integration tests for port scanning workflows."""

    def test_full_scan_workflow(self, test_config, authorized_targets_file, mock_socket, tmp_path):
        """Test complete scan workflow from start to finish."""
        test_config["authorization"]["scope_file"] = authorized_targets_file
        test_config["authorization"]["require_confirmation"] = False
        test_config["output"]["directory"] = str(tmp_path)

        scanner = PortScanner(test_config)
        result = scanner.run("192.168.1.10", "22,80,443")

        # Verify scan completed
        assert result["target"] == "192.168.1.10"
        assert result["total_ports_scanned"] == 3
        assert result["open_ports"] == 3

        # Verify results file was created
        output_files = list(tmp_path.glob("portscan_*.json"))
        assert len(output_files) == 1

    def test_scan_with_rate_limiting(self, test_config, authorized_targets_file, mock_socket):
        """Test scan respects rate limiting."""
        import time

        test_config["authorization"]["scope_file"] = authorized_targets_file
        test_config["authorization"]["require_confirmation"] = False
        test_config["rate_limit"]["requests_per_second"] = 10

        scanner = PortScanner(test_config)

        start_time = time.time()
        scanner.run("192.168.1.10", "80,443,8080")
        elapsed_time = time.time() - start_time

        # Should take at least 0.2 seconds for 3 ports at 10 req/s
        assert elapsed_time >= 0.2
