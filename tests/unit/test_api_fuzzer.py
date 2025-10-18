#!/usr/bin/env python3
"""
Tests for API Fuzzer

Comprehensive unit tests for APIFuzzer class covering:
- Initialization
- BOLA/IDOR testing (API1:2023)
- Broken authentication testing (API2:2023)
- Excessive data exposure (API3:2023)
- Rate limiting testing (API4:2023)
- BFLA testing (API5:2023)
- SSRF testing (API7:2023)
- Security misconfiguration (API8:2023)
- HTTP request handling
- Finding management
"""

from unittest.mock import Mock, patch

import pytest
import requests

from offensive_toolkit.api_security.api_fuzzer import APIFuzzer


class TestAPIFuzzerInit:
    """Tests for APIFuzzer initialization."""

    def test_init_with_base_url(self):
        """Test initialization with base URL."""
        fuzzer = APIFuzzer("https://api.example.com")

        assert fuzzer.base_url == "https://api.example.com"
        assert fuzzer.headers == {}
        assert fuzzer.session is not None
        assert "endpoints_tested" in fuzzer.findings
        assert "bola" in fuzzer.findings
        assert "broken_auth" in fuzzer.findings

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from base URL."""
        fuzzer = APIFuzzer("https://api.example.com/")

        assert fuzzer.base_url == "https://api.example.com"

    def test_init_with_custom_headers(self):
        """Test initialization with custom headers."""
        headers = {"Authorization": "Bearer token123", "X-Custom": "value"}
        fuzzer = APIFuzzer("https://api.example.com", headers=headers)

        assert fuzzer.headers == headers
        assert fuzzer.session.headers["Authorization"] == "Bearer token123"
        assert fuzzer.session.headers["X-Custom"] == "value"

    def test_findings_structure_initialized(self):
        """Test that findings structure is properly initialized."""
        fuzzer = APIFuzzer("https://api.example.com")

        assert "scan_metadata" in fuzzer.findings
        assert "timestamp" in fuzzer.findings["scan_metadata"]
        assert "scanner" in fuzzer.findings["scan_metadata"]
        assert fuzzer.findings["scan_metadata"]["scanner"] == "APIFuzzer"
        assert fuzzer.findings["scan_metadata"]["target_url"] == "https://api.example.com"

        assert fuzzer.findings["bola"] == []
        assert fuzzer.findings["broken_auth"] == []
        assert fuzzer.findings["data_exposure"] == []
        assert fuzzer.findings["rate_limiting"] == []
        assert fuzzer.findings["bfla"] == []
        assert fuzzer.findings["ssrf"] == []
        assert fuzzer.findings["misconfig"] == []

        assert "summary" in fuzzer.findings
        assert fuzzer.findings["summary"]["critical"] == 0
        assert fuzzer.findings["summary"]["high"] == 0


class TestMakeRequest:
    """Tests for _make_request functionality."""

    @patch("requests.Session.request")
    def test_make_request_get(self, mock_request):
        """Test making GET request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'{"data": "value"}'
        mock_request.return_value = mock_response

        fuzzer = APIFuzzer("https://api.example.com")
        response = fuzzer._make_request("GET", "/api/users")

        assert response is not None
        assert response.status_code == 200
        mock_request.assert_called_once()

    @patch("requests.Session.request")
    def test_make_request_post_with_json(self, mock_request):
        """Test making POST request with JSON data."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_request.return_value = mock_response

        fuzzer = APIFuzzer("https://api.example.com")
        response = fuzzer._make_request(
            "POST", "/api/users", json_data={"name": "Test User"}
        )

        assert response is not None
        mock_request.assert_called_once()
        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["json"] == {"name": "Test User"}

    @patch("requests.Session.request")
    def test_make_request_with_custom_headers(self, mock_request):
        """Test making request with custom headers."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        fuzzer = APIFuzzer("https://api.example.com")
        custom_headers = {"X-Test": "value"}
        response = fuzzer._make_request("GET", "/api/test", headers=custom_headers)

        assert response is not None
        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["headers"] == custom_headers

    @patch("requests.Session.request")
    def test_make_request_timeout(self, mock_request):
        """Test request with timeout error."""
        mock_request.side_effect = requests.exceptions.Timeout("Request timeout")

        fuzzer = APIFuzzer("https://api.example.com")
        response = fuzzer._make_request("GET", "/api/slow")

        assert response is None

    @patch("requests.Session.request")
    def test_make_request_connection_error(self, mock_request):
        """Test request with connection error."""
        mock_request.side_effect = requests.exceptions.ConnectionError("Connection failed")

        fuzzer = APIFuzzer("https://api.example.com")
        response = fuzzer._make_request("GET", "/api/test")

        assert response is None


class TestAddFinding:
    """Tests for _add_finding functionality."""

    def test_add_finding_updates_category(self):
        """Test that adding finding updates the category list."""
        fuzzer = APIFuzzer("https://api.example.com")

        finding = {
            "type": "test_finding",
            "endpoint": "/api/test",
            "severity": "high",
            "description": "Test finding",
        }

        fuzzer._add_finding("bola", finding)

        assert len(fuzzer.findings["bola"]) == 1
        assert fuzzer.findings["bola"][0] == finding

    def test_add_finding_updates_severity_count(self):
        """Test that adding finding updates severity counts."""
        fuzzer = APIFuzzer("https://api.example.com")

        finding_critical = {"severity": "critical", "description": "Critical issue"}
        finding_high = {"severity": "high", "description": "High issue"}

        fuzzer._add_finding("bola", finding_critical)
        fuzzer._add_finding("broken_auth", finding_high)

        assert fuzzer.findings["summary"]["critical"] == 1
        assert fuzzer.findings["summary"]["high"] == 1

    def test_add_multiple_findings_same_severity(self):
        """Test adding multiple findings with same severity."""
        fuzzer = APIFuzzer("https://api.example.com")

        for i in range(5):
            finding = {"severity": "medium", "description": f"Finding {i}"}
            fuzzer._add_finding("bola", finding)

        assert fuzzer.findings["summary"]["medium"] == 5
        assert len(fuzzer.findings["bola"]) == 5


class TestBOLA:
    """Tests for test_bola functionality."""

    @patch("requests.Session.request")
    def test_bola_with_default_ids(self, mock_request):
        """Test BOLA testing with default ID range."""
        # Mock 404 responses for all IDs
        mock_response = Mock()
        mock_response.status_code = 404
        mock_request.return_value = mock_response

        fuzzer = APIFuzzer("https://api.example.com")
        fuzzer.test_bola("/api/users/{id}")

        # Should test IDs 1-10 by default (2 requests each: no auth + auth)
        assert mock_request.call_count == 20
        assert "/api/users/{id}" in fuzzer.findings["endpoints_tested"]

    @patch("requests.Session.request")
    def test_bola_detects_no_auth_required(self, mock_request):
        """Test BOLA detection for endpoints without authentication."""
        def mock_response_func(*args, **kwargs):
            response = Mock()
            # No auth header = still returns 200 with data
            if not kwargs.get("headers"):
                response.status_code = 200
                response.json.return_value = {"id": 1, "email": "user@example.com"}
            else:
                response.status_code = 200
                response.json.return_value = {"id": 1, "email": "user@example.com"}
            response.content = b'{"id": 1}'
            return response

        mock_request.side_effect = mock_response_func

        fuzzer = APIFuzzer("https://api.example.com", headers={"Authorization": "Bearer token"})
        fuzzer.test_bola("/api/users/{id}", test_ids=[1])

        # Should find BOLA vulnerability
        assert len(fuzzer.findings["bola"]) > 0
        assert any(f["type"] == "bola_no_auth_required" for f in fuzzer.findings["bola"])

    @patch("requests.Session.request")
    def test_bola_detects_horizontal_privilege_escalation(self, mock_request):
        """Test BOLA detection for horizontal privilege escalation."""
        def mock_response_func(*args, **kwargs):
            response = Mock()
            response.status_code = 200
            # All IDs return same content length (no proper authz)
            response.content = b'{"id": 1, "data": "test"}' * 10
            response.json.return_value = {"id": 1, "data": "test"}
            return response

        mock_request.side_effect = mock_response_func

        fuzzer = APIFuzzer("https://api.example.com", headers={"Authorization": "Bearer token"})
        fuzzer.test_bola("/api/users/{id}", test_ids=[1, 2, 3])

        # Should detect horizontal privilege escalation
        bola_findings = [f for f in fuzzer.findings["bola"] if f["type"] == "bola_horizontal_privilege_escalation"]
        assert len(bola_findings) > 0


class TestBrokenAuthentication:
    """Tests for test_broken_authentication functionality."""

    @patch("requests.Session.request")
    @patch("time.sleep")  # Mock sleep to speed up tests
    def test_detects_no_rate_limiting(self, mock_sleep, mock_request):
        """Test detection of missing rate limiting on auth endpoint."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_request.return_value = mock_response

        fuzzer = APIFuzzer("https://api.example.com")
        test_creds = [("user1", "pass1"), ("user2", "pass2")] * 10  # 20 attempts

        fuzzer.test_broken_authentication("/api/login", test_creds)

        # Should detect no rate limiting
        assert any(f["type"] == "auth_no_rate_limit" for f in fuzzer.findings["broken_auth"])

    @patch("requests.Session.request")
    def test_detects_weak_password(self, mock_request):
        """Test detection of weak password acceptance."""
        def mock_response_func(*args, **kwargs):
            response = Mock()
            json_data = kwargs.get("json")
            # Accept weak password "password"
            if json_data and json_data.get("password") == "password":
                response.status_code = 200
                response.json.return_value = {"token": "abc123"}
            else:
                response.status_code = 401
            return response

        mock_request.side_effect = mock_response_func

        fuzzer = APIFuzzer("https://api.example.com")
        fuzzer.test_broken_authentication("/api/login", [])

        # Should detect weak password
        weak_pass_findings = [f for f in fuzzer.findings["broken_auth"] if "weak_password" in f.get("type", "")]
        assert len(weak_pass_findings) > 0


class TestRateLimiting:
    """Tests for test_rate_limiting functionality."""

    @patch("requests.Session.request")
    @patch("time.time")
    def test_detects_missing_rate_limiting(self, mock_time, mock_request):
        """Test detection of missing rate limiting."""
        mock_time.side_effect = [0, 1]  # 1 second for 100 requests

        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        fuzzer = APIFuzzer("https://api.example.com")
        fuzzer.test_rate_limiting("/api/endpoint", requests_count=100)

        # Should detect no rate limiting if all requests succeed
        assert len(fuzzer.findings["rate_limiting"]) > 0

    @patch("requests.Session.request")
    @patch("time.time")
    def test_detects_rate_limiting_present(self, mock_time, mock_request):
        """Test detection when rate limiting is present."""
        mock_time.side_effect = [0, 10]  # 10 seconds for 100 requests

        def mock_response_func(*args, **kwargs):
            response = Mock()
            # Return 429 after some requests
            if mock_request.call_count > 50:
                response.status_code = 429
            else:
                response.status_code = 200
            return response

        mock_request.side_effect = mock_response_func

        fuzzer = APIFuzzer("https://api.example.com")
        fuzzer.test_rate_limiting("/api/endpoint", requests_count=100)

        # Should not detect missing rate limiting
        no_rate_limit_findings = [f for f in fuzzer.findings["rate_limiting"] if "no_rate_limiting" in f.get("type", "")]
        assert len(no_rate_limit_findings) == 0


class TestBFLA:
    """Tests for test_bfla (Broken Function Level Authorization) functionality."""

    @patch("requests.Session.request")
    def test_detects_bfla_vulnerability(self, mock_request):
        """Test detection of BFLA vulnerability."""
        def mock_response_func(*args, **kwargs):
            response = Mock()
            # Admin endpoint accessible with regular user headers
            response.status_code = 200
            response.content = b'{"admin": "data"}'
            return response

        mock_request.side_effect = mock_response_func

        fuzzer = APIFuzzer("https://api.example.com")
        regular_headers = {"Authorization": "Bearer regular_user_token"}

        fuzzer.test_bfla("/api/admin/users", regular_headers)

        # Should detect BFLA
        assert len(fuzzer.findings["bfla"]) > 0

    @patch("requests.Session.request")
    def test_no_bfla_when_properly_protected(self, mock_request):
        """Test no BFLA when endpoint is properly protected."""
        mock_response = Mock()
        mock_response.status_code = 403  # Forbidden for regular user
        mock_request.return_value = mock_response

        fuzzer = APIFuzzer("https://api.example.com")
        regular_headers = {"Authorization": "Bearer regular_user_token"}

        fuzzer.test_bfla("/api/admin/users", regular_headers)

        # Should not detect BFLA
        assert len(fuzzer.findings["bfla"]) == 0


class TestSSRF:
    """Tests for test_ssrf functionality."""

    @patch("requests.Session.request")
    def test_detects_ssrf_vulnerability(self, mock_request):
        """Test detection of SSRF vulnerability."""
        def mock_response_func(*args, **kwargs):
            response = Mock()
            params = kwargs.get("params", {})
            # If internal URL is accepted, it's vulnerable
            if params.get("url") and ("localhost" in params.get("url") or "127.0.0.1" in params.get("url")):
                response.status_code = 200
                response.content = "root:x:0:0:root:/root:/bin/bash metadata credentials secret"
                response.text = "root:x:0:0:root:/root:/bin/bash metadata credentials secret"
            else:
                response.status_code = 400
                response.content = b"Bad request"
                response.text = "Bad request"
            return response

        mock_request.side_effect = mock_response_func

        fuzzer = APIFuzzer("https://api.example.com")
        fuzzer.test_ssrf("/api/fetch")

        # Should detect SSRF
        assert len(fuzzer.findings["ssrf"]) > 0

    @patch("requests.Session.request")
    def test_no_ssrf_when_properly_validated(self, mock_request):
        """Test no SSRF when URL validation is proper."""
        mock_response = Mock()
        mock_response.status_code = 400  # Bad request for internal URLs
        mock_request.return_value = mock_response

        fuzzer = APIFuzzer("https://api.example.com")
        fuzzer.test_ssrf("/api/fetch")

        # Should not detect SSRF
        assert len(fuzzer.findings["ssrf"]) == 0


class TestSecurityMisconfiguration:
    """Tests for test_security_misconfiguration functionality."""

    @patch("requests.Session.request")
    def test_detects_verbose_error_messages(self, mock_request):
        """Test detection of verbose error messages."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Stack trace: Exception in module main.py database error"
        mock_response.headers = {}  # Empty dict for header checks
        mock_request.return_value = mock_response

        fuzzer = APIFuzzer("https://api.example.com")
        fuzzer.test_security_misconfiguration(["/api/test"])

        # Should detect verbose error
        verbose_errors = [f for f in fuzzer.findings["misconfig"] if "verbose" in f.get("type", "").lower()]
        assert len(verbose_errors) > 0

    @patch("requests.Session.request")
    def test_detects_cors_wildcard(self, mock_request):
        """Test detection of CORS wildcard misconfiguration."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_response.headers = {"Access-Control-Allow-Origin": "*"}
        mock_request.return_value = mock_response

        fuzzer = APIFuzzer("https://api.example.com")
        fuzzer.test_security_misconfiguration(["/api/test"])

        # Should detect CORS wildcard
        cors_findings = [f for f in fuzzer.findings["misconfig"] if "cors" in f.get("type", "").lower()]
        assert len(cors_findings) > 0

    @patch("requests.Session.request")
    def test_detects_missing_security_headers(self, mock_request):
        """Test detection of missing security headers."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}  # No security headers
        mock_response.text = "OK"
        mock_request.return_value = mock_response

        fuzzer = APIFuzzer("https://api.example.com")
        fuzzer.test_security_misconfiguration(["/api/test"])

        # Should detect missing security headers
        header_findings = [f for f in fuzzer.findings["misconfig"] if "header" in f.get("type", "").lower()]
        assert len(header_findings) > 0


class TestSaveResults:
    """Tests for save_results functionality."""

    def test_save_results_creates_json_file(self, temp_dir):
        """Test that save_results creates JSON file."""
        fuzzer = APIFuzzer("https://api.example.com")
        fuzzer._add_finding("bola", {"type": "test", "severity": "high"})

        output_file = temp_dir / "results.json"
        fuzzer.save_results(output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert "APIFuzzer" in content
        assert "bola" in content


class TestAPIFuzzerIntegration:
    """Integration tests for APIFuzzer."""

    @patch("requests.Session.request")
    def test_full_scan_workflow(self, mock_request):
        """Test complete API fuzzing workflow."""
        def mock_response_func(*args, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = b'{"data": "value"}'
            response.headers = {}
            response.text = "OK"
            response.json.return_value = {"data": "value"}
            return response

        mock_request.side_effect = mock_response_func

        fuzzer = APIFuzzer("https://api.example.com", headers={"Authorization": "Bearer token"})

        # Run multiple tests
        fuzzer.test_bola("/api/users/{id}", test_ids=[1, 2])
        fuzzer.test_rate_limiting("/api/endpoint", requests_count=10)
        fuzzer.test_security_misconfiguration(["/api/test"])

        # Verify findings structure
        assert len(fuzzer.findings["endpoints_tested"]) > 0
        assert "scan_metadata" in fuzzer.findings
        assert fuzzer.findings["scan_metadata"]["target_url"] == "https://api.example.com"
