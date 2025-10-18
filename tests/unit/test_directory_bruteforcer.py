#!/usr/bin/env python3
"""
Tests for Directory Bruteforcer

Comprehensive unit tests for DirectoryBruteforcer class covering:
- Initialization
- Path testing with various status codes
- Wordlist loading
- Full brute-force runs
- Error handling
- Rate limiting
- Integration scenarios
"""

from unittest.mock import Mock, patch

import pytest
import requests

from offensive_toolkit.web_security.directory_bruteforcer import DirectoryBruteforcer


class TestDirectoryBruteforcerInit:
    """Tests for DirectoryBruteforcer initialization."""

    def test_init_with_config(self, test_config):
        """Test initialization with provided config."""
        bruteforcer = DirectoryBruteforcer(config=test_config)

        assert bruteforcer is not None
        assert bruteforcer.config == test_config
        assert bruteforcer.session is not None
        assert bruteforcer.rate_limiter is not None

    def test_init_without_config(self):
        """Test initialization without config (uses default)."""
        bruteforcer = DirectoryBruteforcer()

        assert bruteforcer is not None
        assert bruteforcer.config is not None
        assert bruteforcer.session is not None

    def test_user_agent_set(self, test_config):
        """Test that User-Agent header is set from config."""
        test_config["user_agent"] = "TestAgent/1.0"
        bruteforcer = DirectoryBruteforcer(config=test_config)

        assert bruteforcer.session.headers.get("User-Agent") == "TestAgent/1.0"


class TestLoadWordlist:
    """Tests for wordlist loading functionality."""

    def test_load_valid_wordlist(self, test_config, temp_dir):
        """Test loading valid wordlist from file."""
        wordlist_file = temp_dir / "wordlist.txt"
        wordlist_file.write_text("admin\nlogin\ntest\n")

        bruteforcer = DirectoryBruteforcer(test_config)
        wordlist = bruteforcer._load_wordlist(str(wordlist_file))

        assert len(wordlist) == 3
        assert "admin" in wordlist
        assert "login" in wordlist
        assert "test" in wordlist

    def test_load_wordlist_strips_whitespace(self, test_config, temp_dir):
        """Test that wordlist loading strips whitespace."""
        wordlist_file = temp_dir / "wordlist.txt"
        wordlist_file.write_text("  admin  \n\tlogin\t\n  test\n")

        bruteforcer = DirectoryBruteforcer(test_config)
        wordlist = bruteforcer._load_wordlist(str(wordlist_file))

        assert len(wordlist) == 3
        assert wordlist == ["admin", "login", "test"]

    def test_load_wordlist_skips_empty_lines(self, test_config, temp_dir):
        """Test that empty lines are skipped."""
        wordlist_file = temp_dir / "wordlist.txt"
        wordlist_file.write_text("admin\n\n\nlogin\n  \ntest\n")

        bruteforcer = DirectoryBruteforcer(test_config)
        wordlist = bruteforcer._load_wordlist(str(wordlist_file))

        assert len(wordlist) == 3
        assert wordlist == ["admin", "login", "test"]

    def test_load_nonexistent_wordlist(self, test_config):
        """Test loading nonexistent wordlist returns empty list."""
        bruteforcer = DirectoryBruteforcer(test_config)
        wordlist = bruteforcer._load_wordlist("nonexistent.txt")

        assert wordlist == []

    def test_load_empty_wordlist_file(self, test_config, temp_dir):
        """Test loading empty wordlist file."""
        wordlist_file = temp_dir / "empty.txt"
        wordlist_file.write_text("")

        bruteforcer = DirectoryBruteforcer(test_config)
        wordlist = bruteforcer._load_wordlist(str(wordlist_file))

        assert wordlist == []


class TestPathTesting:
    """Tests for test_path functionality."""

    @patch("requests.Session.get")
    def test_test_path_status_200(self, mock_get, test_config):
        """Test path with 200 OK status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"Admin panel content"
        mock_response.headers = {}
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/admin")

        assert result is not None
        assert result["status_code"] == 200
        assert result["url"] == "https://example.com/admin"
        assert result["content_length"] == 19

    @patch("requests.Session.get")
    def test_test_path_status_204(self, mock_get, test_config):
        """Test path with 204 No Content status."""
        mock_response = Mock()
        mock_response.status_code = 204
        mock_response.content = b""
        mock_response.headers = {}
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/api/endpoint")

        assert result is not None
        assert result["status_code"] == 204

    @patch("requests.Session.get")
    def test_test_path_status_301(self, mock_get, test_config):
        """Test path with 301 redirect."""
        mock_response = Mock()
        mock_response.status_code = 301
        mock_response.content = b"Redirect"
        mock_response.headers = {"Location": "https://example.com/new-admin"}
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/old-admin")

        assert result is not None
        assert result["status_code"] == 301
        assert result["redirect"] == "https://example.com/new-admin"

    @patch("requests.Session.get")
    def test_test_path_status_302(self, mock_get, test_config):
        """Test path with 302 redirect."""
        mock_response = Mock()
        mock_response.status_code = 302
        mock_response.content = b"Redirect"
        mock_response.headers = {"Location": "/login"}
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/admin")

        assert result is not None
        assert result["status_code"] == 302
        assert result["redirect"] == "/login"

    @patch("requests.Session.get")
    def test_test_path_status_401(self, mock_get, test_config):
        """Test path with 401 Unauthorized status."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.content = b"Unauthorized"
        mock_response.headers = {}
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/private")

        assert result is not None
        assert result["status_code"] == 401

    @patch("requests.Session.get")
    def test_test_path_status_403(self, mock_get, test_config):
        """Test path with 403 Forbidden status."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.content = b"Forbidden"
        mock_response.headers = {}
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/restricted")

        assert result is not None
        assert result["status_code"] == 403

    @patch("requests.Session.get")
    def test_test_path_status_404(self, mock_get, test_config):
        """Test path with 404 Not Found status (not interesting)."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.content = b"Not found"
        mock_response.headers = {}
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/nonexistent")

        assert result is None

    @patch("requests.Session.get")
    def test_test_path_status_500(self, mock_get, test_config):
        """Test path with 500 status (not interesting)."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/error")

        assert result is None

    @patch("requests.Session.get")
    def test_test_path_with_timeout(self, mock_get, test_config):
        """Test path testing with timeout error."""
        mock_get.side_effect = requests.Timeout("Connection timeout")

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/slow")

        assert result is None

    @patch("requests.Session.get")
    def test_test_path_with_connection_error(self, mock_get, test_config):
        """Test path testing with connection error."""
        mock_get.side_effect = requests.ConnectionError("Connection refused")

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/admin")

        assert result is None

    @patch("requests.Session.get")
    def test_test_path_uses_timeout_from_config(self, mock_get, test_config):
        """Test that timeout from config is used."""
        test_config["timeouts"] = {"connection": 15}
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"OK"
        mock_response.headers = {}
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        bruteforcer.test_path("https://example.com", "/test")

        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["timeout"] == 15


class TestRun:
    """Tests for run functionality."""

    @patch("offensive_toolkit.web_security.directory_bruteforcer.check_authorization")
    @patch("requests.Session.get")
    def test_run_successful_bruteforce(self, mock_get, mock_auth, test_config, temp_dir):
        """Test successful directory brute-force."""
        mock_auth.return_value = True

        # Create wordlist
        wordlist_file = temp_dir / "wordlist.txt"
        wordlist_file.write_text("admin\nlogin\ntest\n")

        # Mock responses
        def get_response(url, **kwargs):
            mock_response = Mock()
            if "admin" in url:
                mock_response.status_code = 200
                mock_response.content = b"Admin panel"
            elif "login" in url:
                mock_response.status_code = 200
                mock_response.content = b"Login page"
            else:
                mock_response.status_code = 404
                mock_response.content = b"Not found"
            mock_response.headers = {}
            return mock_response

        mock_get.side_effect = get_response

        bruteforcer = DirectoryBruteforcer(test_config)
        results = bruteforcer.run("https://example.com", str(wordlist_file))

        assert "error" not in results
        assert results["target"] == "https://example.com"
        assert results["paths_tested"] == 3
        assert results["paths_found"] == 2
        assert len(results["results"]) == 2

    @patch("offensive_toolkit.web_security.directory_bruteforcer.check_authorization")
    def test_run_not_authorized(self, mock_auth, test_config, temp_dir):
        """Test run with unauthorized target."""
        mock_auth.return_value = False

        wordlist_file = temp_dir / "wordlist.txt"
        wordlist_file.write_text("admin\n")

        bruteforcer = DirectoryBruteforcer(test_config)
        results = bruteforcer.run("https://example.com", str(wordlist_file))

        assert "error" in results
        assert results["error"] == "Not authorized"

    @patch("offensive_toolkit.web_security.directory_bruteforcer.check_authorization")
    @patch("offensive_toolkit.web_security.directory_bruteforcer.validate_target")
    def test_run_invalid_url(self, mock_validate, mock_auth, test_config, temp_dir):
        """Test run with invalid URL."""
        mock_auth.return_value = True
        mock_validate.return_value = False

        wordlist_file = temp_dir / "wordlist.txt"
        wordlist_file.write_text("admin\n")

        bruteforcer = DirectoryBruteforcer(test_config)
        results = bruteforcer.run("not-a-url", str(wordlist_file))

        assert "error" in results
        assert results["error"] == "Invalid URL"

    @patch("offensive_toolkit.web_security.directory_bruteforcer.check_authorization")
    def test_run_empty_wordlist(self, mock_auth, test_config):
        """Test run with empty wordlist."""
        mock_auth.return_value = True

        bruteforcer = DirectoryBruteforcer(test_config)
        results = bruteforcer.run("https://example.com", "nonexistent.txt")

        assert "error" in results
        assert results["error"] == "Empty or invalid wordlist"

    @patch("offensive_toolkit.web_security.directory_bruteforcer.check_authorization")
    @patch("requests.Session.get")
    def test_run_no_paths_found(self, mock_get, mock_auth, test_config, temp_dir):
        """Test run where no paths are found."""
        mock_auth.return_value = True

        wordlist_file = temp_dir / "wordlist.txt"
        wordlist_file.write_text("admin\nlogin\n")

        # All paths return 404
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.headers = {}
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        results = bruteforcer.run("https://example.com", str(wordlist_file))

        assert "error" not in results
        assert results["paths_found"] == 0
        assert len(results["results"]) == 0


class TestRateLimiting:
    """Tests for rate limiting."""

    @patch("offensive_toolkit.web_security.directory_bruteforcer.check_authorization")
    @patch("requests.Session.get")
    def test_rate_limiting_applied(self, mock_get, mock_auth, test_config, temp_dir):
        """Test that rate limiting is applied during brute-force."""
        mock_auth.return_value = True
        test_config["rate_limit"] = {"requests_per_second": 100}  # Fast for testing

        wordlist_file = temp_dir / "wordlist.txt"
        wordlist_file.write_text("admin\nlogin\ntest\n")

        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.headers = {}
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)

        # Mock the rate limiter to verify it's called
        with patch.object(bruteforcer.rate_limiter, "wait") as mock_wait:
            bruteforcer.run("https://example.com", str(wordlist_file))

            # Rate limiter should be called for each path
            assert mock_wait.call_count == 3


class TestDirectoryBruteforcerIntegration:
    """Integration tests for DirectoryBruteforcer."""

    @patch("offensive_toolkit.web_security.directory_bruteforcer.check_authorization")
    @patch("requests.Session.get")
    def test_full_bruteforce_workflow(self, mock_get, mock_auth, test_config, temp_dir):
        """Test complete brute-force workflow."""
        mock_auth.return_value = True

        # Create realistic wordlist
        wordlist_file = temp_dir / "common.txt"
        wordlist_file.write_text(
            "admin\nlogin\ntest\nbackup\nconfig\nprivate\napi\nwp-admin\n"
        )

        # Mock realistic responses
        def get_response(url, **kwargs):
            mock_response = Mock()
            mock_response.headers = {}

            if "/admin" in url:
                mock_response.status_code = 401  # Protected
                mock_response.content = b"Unauthorized"
            elif "/login" in url:
                mock_response.status_code = 200
                mock_response.content = b"<form>Login</form>"
            elif "/backup" in url:
                mock_response.status_code = 403  # Forbidden
                mock_response.content = b"Forbidden"
            elif "/api" in url:
                mock_response.status_code = 301  # Redirect
                mock_response.headers["Location"] = "https://api.example.com"
                mock_response.content = b"Redirect"
            else:
                mock_response.status_code = 404
                mock_response.content = b"Not found"

            return mock_response

        mock_get.side_effect = get_response

        bruteforcer = DirectoryBruteforcer(test_config)
        results = bruteforcer.run("https://example.com", str(wordlist_file))

        # Verify results
        assert "error" not in results
        assert results["target"] == "https://example.com"
        assert results["paths_tested"] == 8
        assert results["paths_found"] == 4  # admin (401), login (200), backup (403), api (301)

        # Verify specific findings
        found_urls = [r["url"] for r in results["results"]]
        assert "https://example.com/admin" in found_urls
        assert "https://example.com/login" in found_urls
        assert "https://example.com/backup" in found_urls
        assert "https://example.com/api" in found_urls
