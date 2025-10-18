#!/usr/bin/env python3
"""
Tests for SQL Injection Scanner

Comprehensive unit tests for SQLInjectionScanner class covering:
- Initialization
- Error-based injection detection
- Time-based injection detection
- Boolean-based injection detection
- Union-based injection detection
- URL scanning workflow
- Edge cases and error handling
"""

import time
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests

from offensive_toolkit.web_security.sql_injection import (
    PAYLOADS,
    SQL_ERRORS,
    InjectionType,
    SQLInjectionScanner,
)


@pytest.fixture
def test_config() -> dict[str, Any]:
    """Provide test configuration."""
    return {
        "rate_limit": {"requests_per_second": 10},
        "timeouts": {"connection": 5},
        "http": {"user_agent": "TestScanner/1.0"},
        "output": {"directory": "test_output"},
        "authorization": {
            "require_explicit": False,
            "allowed_targets": ["192.168.1.0/24", "10.0.0.0/8"],
        },
    }


class TestSQLInjectionScannerInit:
    """Tests for SQLInjectionScanner initialization."""

    def test_init_with_config(self, test_config):
        """Test initialization with custom config."""
        scanner = SQLInjectionScanner(config=test_config)

        assert scanner.config == test_config
        assert scanner.rate_limiter is not None
        assert scanner.session is not None
        assert scanner.vulnerabilities == []

    def test_init_without_config(self):
        """Test initialization without config (uses defaults)."""
        with patch("offensive_toolkit.web_security.sql_injection.load_config") as mock_load:
            mock_load.return_value = {"rate_limit": {"requests_per_second": 5}}

            scanner = SQLInjectionScanner()

            assert scanner.config is not None
            assert scanner.rate_limiter is not None
            mock_load.assert_called_once()

    def test_session_has_user_agent(self, test_config):
        """Test that session is configured with user agent."""
        scanner = SQLInjectionScanner(config=test_config)

        assert "User-Agent" in scanner.session.headers
        assert scanner.session.headers["User-Agent"] == "TestScanner/1.0"


class TestInjectionType:
    """Tests for InjectionType enum."""

    def test_injection_types_exist(self):
        """Test all injection types are defined."""
        assert InjectionType.UNION.value == "union"
        assert InjectionType.BOOLEAN.value == "boolean"
        assert InjectionType.TIME_BASED.value == "time-based"
        assert InjectionType.ERROR_BASED.value == "error-based"

    def test_payloads_for_all_types(self):
        """Test payloads defined for all injection types."""
        for inj_type in InjectionType:
            assert inj_type in PAYLOADS
            assert len(PAYLOADS[inj_type]) > 0

    def test_sql_errors_list_exists(self):
        """Test SQL error patterns list is populated."""
        assert isinstance(SQL_ERRORS, list)
        assert len(SQL_ERRORS) > 0
        # Check for common database errors
        error_str = " ".join(SQL_ERRORS)
        assert "MySQL" in error_str
        assert "PostgreSQL" in error_str
        assert "SQL Server" in error_str


class TestErrorBasedInjection:
    """Tests for error-based SQL injection detection."""

    def test_detect_mysql_error(self, test_config):
        """Test detecting MySQL error in response."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
            mock_response.status_code = 500
            mock_get.return_value = mock_response

            result = scanner.test_injection(
                "http://example.com/page?id=1",
                "id",
                "'",
                InjectionType.ERROR_BASED
            )

            assert result is not None
            assert result["type"] == "error-based"
            assert result["parameter"] == "id"
            assert result["payload"] == "'"
            assert "SQL error pattern detected" in result["evidence"]
            assert result["confidence"] == "high"

    def test_detect_postgresql_error(self, test_config):
        """Test detecting PostgreSQL error in response."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.text = "PostgreSQL ERROR: syntax error at or near"
            mock_get.return_value = mock_response

            result = scanner.test_injection(
                "http://example.com/search?q=test",
                "q",
                "\\",
                InjectionType.ERROR_BASED
            )

            assert result is not None
            assert result["type"] == "error-based"
            assert result["confidence"] == "high"

    def test_no_error_detected(self, test_config):
        """Test when no SQL error is present."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.text = "No results found for your search query"
            mock_get.return_value = mock_response

            result = scanner.test_injection(
                "http://example.com/search?q=test",
                "q",
                "'",
                InjectionType.ERROR_BASED
            )

            assert result is None


class TestTimeBasedInjection:
    """Tests for time-based SQL injection detection."""

    def test_detect_time_delay(self, test_config):
        """Test detecting time-based injection via delay."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.text = "Success"
            mock_get.return_value = mock_response

            # Patch time.time in the sql_injection module
            with patch("offensive_toolkit.web_security.sql_injection.time") as mock_time_module:
                # Mock time() calls to simulate 5+ second delay
                mock_time_module.time.side_effect = [0, 6.5]  # Start: 0, End: 6.5

                result = scanner.test_injection(
                    "http://example.com/page?id=1",
                    "id",
                    "' AND SLEEP(5)--",
                    InjectionType.TIME_BASED
                )

                assert result is not None
                assert result["type"] == "time-based"
                assert result["confidence"] == "high"
                assert "6.50s" in result["evidence"]

    def test_timeout_indicates_time_injection(self, test_config):
        """Test timeout exception indicates time-based SQLi."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout("Request timed out")

            result = scanner.test_injection(
                "http://example.com/page?id=1",
                "id",
                "'; WAITFOR DELAY '00:00:05'--",
                InjectionType.TIME_BASED
            )

            assert result is not None
            assert result["type"] == "time-based"
            assert result["confidence"] == "medium"
            assert "timeout" in result["evidence"].lower()

    def test_no_time_delay(self, test_config):
        """Test when response is fast (no injection)."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.text = "Success"
            mock_get.return_value = mock_response

            with patch("offensive_toolkit.web_security.sql_injection.time.time") as mock_time:
                mock_time.side_effect = [0, 0.5]  # Only 0.5s elapsed

                result = scanner.test_injection(
                    "http://example.com/page?id=1",
                    "id",
                    "' AND SLEEP(5)--",
                    InjectionType.TIME_BASED
                )

                assert result is None


class TestBooleanBasedInjection:
    """Tests for boolean-based SQL injection detection."""

    def test_boolean_injection_detected(self, test_config):
        """Test detecting boolean-based injection."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.text = "Welcome, admin! You have 10 messages."
            mock_get.return_value = mock_response

            result = scanner.test_injection(
                "http://example.com/login?user=admin",
                "user",
                "' OR '1'='1",
                InjectionType.BOOLEAN
            )

            assert result is not None
            assert result["type"] == "boolean"
            assert result["parameter"] == "user"
            assert result["confidence"] == "low"  # Requires manual verification

    def test_boolean_empty_response(self, test_config):
        """Test boolean with empty response."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.text = ""
            mock_get.return_value = mock_response

            result = scanner.test_injection(
                "http://example.com/check?id=1",
                "id",
                "' OR 1=1--",
                InjectionType.BOOLEAN
            )

            assert result is None


class TestUnionBasedInjection:
    """Tests for UNION-based SQL injection detection."""

    def test_union_with_null_in_response(self, test_config):
        """Test detecting UNION injection when NULL appears in response."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.text = "Results: NULL | NULL | admin | admin@example.com"
            mock_get.return_value = mock_response

            result = scanner.test_injection(
                "http://example.com/user?id=1",
                "id",
                "' UNION SELECT NULL,NULL--",
                InjectionType.UNION
            )

            assert result is not None
            assert result["type"] == "union"
            assert result["confidence"] == "medium"
            assert "UNION-related data" in result["evidence"]

    def test_union_with_information_schema(self, test_config):
        """Test detecting UNION with information_schema disclosure."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.text = "Table: users from information_schema.tables"
            mock_get.return_value = mock_response

            result = scanner.test_injection(
                "http://example.com/data?table=users",
                "table",
                "-1' UNION SELECT NULL,table_name FROM information_schema.tables--",
                InjectionType.UNION
            )

            assert result is not None
            assert result["type"] == "union"

    def test_union_not_detected(self, test_config):
        """Test when UNION is not present in response."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.text = "User details: John Doe, john@example.com"
            mock_get.return_value = mock_response

            result = scanner.test_injection(
                "http://example.com/user?id=1",
                "id",
                "' UNION SELECT NULL--",
                InjectionType.UNION
            )

            assert result is None


class TestPOSTInjection:
    """Tests for SQL injection via POST method."""

    def test_post_error_based(self, test_config):
        """Test error-based injection via POST."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "post") as mock_post:
            mock_response = Mock()
            mock_response.text = "Microsoft SQL Native Client error: Unclosed quotation mark"
            mock_post.return_value = mock_response

            result = scanner.test_injection(
                "http://example.com/login",
                "username",
                "admin' --",
                InjectionType.ERROR_BASED,
                method="POST",
                data={"password": "test"}
            )

            assert result is not None
            assert result["type"] == "error-based"
            assert result["parameter"] == "username"
            # Verify POST was called with injected data
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[1]["data"]["username"] == "admin' --"
            assert call_args[1]["data"]["password"] == "test"


class TestScanURL:
    """Tests for scan_url method."""

    def test_scan_single_parameter(self, test_config):
        """Test scanning single parameter."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner, "test_injection") as mock_test:
            vuln = {
                "type": "error-based",
                "parameter": "id",
                "payload": "'",
                "evidence": "SQL error detected",
                "confidence": "high"
            }
            mock_test.side_effect = [vuln, None, None]

            results = scanner.scan_url(
                "http://example.com/page?id=1",
                injection_types=[InjectionType.ERROR_BASED]
            )

            assert len(results) == 1
            assert results[0]["type"] == "error-based"
            # Should stop after first vuln found for this param/type combo
            assert mock_test.call_count >= 1

    def test_scan_multiple_parameters(self, test_config):
        """Test scanning multiple parameters."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner, "test_injection") as mock_test:
            mock_test.return_value = None

            scanner.scan_url(
                "http://example.com/search?q=test&category=all&sort=asc",
                injection_types=[InjectionType.ERROR_BASED]
            )

            # Should test all 3 parameters
            called_params = {call[0][1] for call in mock_test.call_args_list}
            assert "q" in called_params
            assert "category" in called_params
            assert "sort" in called_params

    def test_scan_with_all_injection_types(self, test_config):
        """Test scanning with all injection types."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner, "test_injection") as mock_test:
            mock_test.return_value = None

            all_types = [InjectionType.UNION, InjectionType.BOOLEAN, InjectionType.TIME_BASED, InjectionType.ERROR_BASED]

            scanner.scan_url(
                "http://example.com/page?id=1",
                injection_types=all_types
            )

            # Should test all injection types
            tested_types = {call[0][3] for call in mock_test.call_args_list}
            assert tested_types == set(all_types)

    def test_scan_no_parameters(self, test_config):
        """Test scanning URL with no parameters."""
        scanner = SQLInjectionScanner(config=test_config)

        results = scanner.scan_url("http://example.com/")

        assert results == []


class TestRateLimiting:
    """Tests for rate limiting."""

    def test_rate_limiting_applied(self, test_config):
        """Test rate limiter is called during injection testing."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get"), patch.object(scanner.rate_limiter, "wait") as mock_wait:
            mock_response = Mock()
            mock_response.text = "No error"
            scanner.session.get.return_value = mock_response

            scanner.test_injection(
                "http://example.com/page?id=1",
                "id",
                "'",
                InjectionType.ERROR_BASED
            )

            mock_wait.assert_called()


class TestErrorHandling:
    """Tests for error handling and edge cases."""

    def test_connection_error(self, test_config):
        """Test handling connection errors."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")

            result = scanner.test_injection(
                "http://invalid.example.com/page?id=1",
                "id",
                "'",
                InjectionType.ERROR_BASED
            )

            assert result is None

    def test_generic_exception(self, test_config):
        """Test handling generic exceptions."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner.session, "get") as mock_get:
            mock_get.side_effect = Exception("Unexpected error")

            result = scanner.test_injection(
                "http://example.com/page?id=1",
                "id",
                "'",
                InjectionType.ERROR_BASED
            )

            assert result is None


class TestSQLInjectionIntegration:
    """Integration tests for SQL injection scanner."""

    @pytest.mark.integration
    def test_full_scan_workflow(self, test_config):
        """Test complete scan workflow finding vulnerability."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner, "test_injection") as mock_test:
            # First error-based payload finds vuln
            vuln = {
                "type": "error-based",
                "parameter": "id",
                "payload": "'",
                "evidence": "MySQL error",
                "confidence": "high"
            }
            mock_test.side_effect = [vuln]

            results = scanner.scan_url(
                "http://example.com/user?id=1",
                injection_types=[InjectionType.ERROR_BASED]
            )

            assert len(results) == 1
            assert results[0]["type"] == "error-based"
            assert results[0]["confidence"] == "high"

    @pytest.mark.integration
    def test_no_vulnerabilities_found(self, test_config):
        """Test scan with no vulnerabilities."""
        scanner = SQLInjectionScanner(config=test_config)

        with patch.object(scanner, "test_injection") as mock_test:
            mock_test.return_value = None

            results = scanner.scan_url(
                "http://example.com/secure?id=1",
                injection_types=[InjectionType.ERROR_BASED, InjectionType.BOOLEAN]
            )

            assert len(results) == 0
            assert mock_test.call_count > 0
