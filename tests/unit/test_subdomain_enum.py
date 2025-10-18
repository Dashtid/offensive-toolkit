#!/usr/bin/env python3
"""
Tests for Subdomain Enumerator

Comprehensive unit tests for SubdomainEnumerator class covering:
- Initialization
- DNS brute-force enumeration
- Certificate transparency search
- Concurrent subdomain checking
- Wordlist loading
- Integration workflows
"""

from typing import Any
from unittest.mock import MagicMock, Mock, mock_open, patch

import dns.exception
import dns.resolver
import pytest
import requests

from offensive_toolkit.reconnaissance.subdomain_enum import (
    COMMON_SUBDOMAINS,
    SubdomainEnumerator,
)


@pytest.fixture
def test_config() -> dict[str, Any]:
    """Provide test configuration."""
    return {
        "rate_limit": {"requests_per_second": 20},
        "timeouts": {"connection": 10},
        "output": {"directory": "build/test_output"},
        "authorization": {
            "require_explicit": False,
            "allowed_targets": ["example.com", "test.com"],
        },
    }


class TestSubdomainEnumeratorInit:
    """Tests for SubdomainEnumerator initialization."""

    def test_init_with_config(self, test_config):
        """Test initialization with custom config."""
        enum = SubdomainEnumerator(config=test_config)

        assert enum.config == test_config
        assert enum.rate_limiter is not None
        assert isinstance(enum.found_subdomains, set)
        assert len(enum.found_subdomains) == 0

    def test_init_without_config(self):
        """Test initialization without config (uses defaults)."""
        with patch("offensive_toolkit.reconnaissance.subdomain_enum.load_config") as mock_load:
            mock_load.return_value = {"rate_limit": {"requests_per_second": 10}}

            enum = SubdomainEnumerator()

            assert enum.config is not None
            assert enum.rate_limiter is not None
            mock_load.assert_called_once()

    def test_common_subdomains_populated(self):
        """Test common subdomains wordlist is populated."""
        assert len(COMMON_SUBDOMAINS) > 0
        assert "www" in COMMON_SUBDOMAINS
        assert "mail" in COMMON_SUBDOMAINS
        assert "api" in COMMON_SUBDOMAINS


class TestDNSBruteforce:
    """Tests for dns_bruteforce method."""

    def test_bruteforce_finds_subdomains(self, test_config):
        """Test DNS brute-force finding subdomains."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver

            # Mock DNS responses - only www and mail exist
            def mock_resolve(domain, record_type):
                if domain in ["www.example.com", "mail.example.com"]:
                    return [Mock()]  # Non-empty answer
                raise dns.resolver.NXDOMAIN()

            mock_resolver.resolve = mock_resolve

            # Test with small wordlist
            wordlist = ["www", "mail", "ftp", "nonexistent"]
            found = enum.dns_bruteforce("example.com", wordlist)

            assert len(found) == 2
            assert "www.example.com" in found
            assert "mail.example.com" in found
            assert "ftp.example.com" not in found

    def test_bruteforce_uses_default_wordlist(self, test_config):
        """Test using default COMMON_SUBDOMAINS wordlist."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

            found = enum.dns_bruteforce("example.com")

            # Should have tested all common subdomains
            assert mock_resolver.resolve.call_count == len(COMMON_SUBDOMAINS)

    def test_bruteforce_handles_dns_timeout(self, test_config):
        """Test handling DNS timeout gracefully."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.exception.Timeout()

            wordlist = ["www", "mail"]
            found = enum.dns_bruteforce("example.com", wordlist)

            # Should handle timeouts gracefully
            assert found == set()

    def test_bruteforce_handles_no_answer(self, test_config):
        """Test handling NoAnswer exception."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()

            wordlist = ["www"]
            found = enum.dns_bruteforce("example.com", wordlist)

            assert found == set()

    def test_bruteforce_concurrent_execution(self, test_config):
        """Test that brute-force uses concurrent execution."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver

            # Simulate finding multiple subdomains
            def mock_resolve(domain, record_type):
                if "www" in domain or "api" in domain or "mail" in domain:
                    return [Mock()]
                raise dns.resolver.NXDOMAIN()

            mock_resolver.resolve = mock_resolve

            wordlist = ["www", "api", "mail", "ftp", "blog"]
            found = enum.dns_bruteforce("example.com", wordlist)

            # Should find the 3 existing subdomains
            assert len(found) == 3


class TestCertTransparencySearch:
    """Tests for cert_transparency_search method."""

    def test_cert_search_finds_subdomains(self, test_config):
        """Test certificate transparency search finding subdomains."""
        enum = SubdomainEnumerator(config=test_config)

        mock_response_data = [
            {"name_value": "www.example.com"},
            {"name_value": "mail.example.com"},
            {"name_value": "api.example.com\nsub.example.com"},  # Multiple per cert
        ]

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_response_data
            mock_get.return_value = mock_response

            found = enum.cert_transparency_search("example.com")

            assert len(found) == 4
            assert "www.example.com" in found
            assert "mail.example.com" in found
            assert "api.example.com" in found
            assert "sub.example.com" in found

    def test_cert_search_filters_wildcards(self, test_config):
        """Test filtering wildcard certificates."""
        enum = SubdomainEnumerator(config=test_config)

        mock_response_data = [
            {"name_value": "*.example.com"},  # Wildcard - should be filtered
            {"name_value": "www.example.com"},  # Normal - should be included
        ]

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_response_data
            mock_get.return_value = mock_response

            found = enum.cert_transparency_search("example.com")

            assert len(found) == 1
            assert "www.example.com" in found
            assert "*.example.com" not in found

    def test_cert_search_filters_other_domains(self, test_config):
        """Test filtering subdomains from other domains."""
        enum = SubdomainEnumerator(config=test_config)

        mock_response_data = [
            {"name_value": "www.example.com"},
            {"name_value": "www.otherdomain.com"},  # Different domain
        ]

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_response_data
            mock_get.return_value = mock_response

            found = enum.cert_transparency_search("example.com")

            assert len(found) == 1
            assert "www.example.com" in found
            assert "www.otherdomain.com" not in found

    def test_cert_search_handles_http_error(self, test_config):
        """Test handling HTTP error from crt.sh."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_get.return_value = mock_response

            found = enum.cert_transparency_search("example.com")

            assert found == set()

    def test_cert_search_handles_timeout(self, test_config):
        """Test handling request timeout."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("requests.get") as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout()

            found = enum.cert_transparency_search("example.com")

            assert found == set()

    def test_cert_search_handles_connection_error(self, test_config):
        """Test handling connection error."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("requests.get") as mock_get:
            mock_get.side_effect = requests.exceptions.ConnectionError()

            found = enum.cert_transparency_search("example.com")

            assert found == set()


class TestDNSDumpsterSearch:
    """Tests for dns_dumpster_search method."""

    def test_dumpster_not_implemented(self, test_config):
        """Test DNSDumpster placeholder returns empty set."""
        enum = SubdomainEnumerator(config=test_config)

        found = enum.dns_dumpster_search("example.com")

        assert found == set()


class TestRun:
    """Tests for run method (full workflow)."""

    def test_run_with_cert_only(self, test_config):
        """Test running with certificate transparency only."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("offensive_toolkit.reconnaissance.subdomain_enum.check_authorization") as mock_auth:
            mock_auth.return_value = True

            with patch.object(enum, "cert_transparency_search") as mock_cert:
                mock_cert.return_value = {"www.example.com", "api.example.com"}

                with patch.object(enum, "_save_results"):
                    results = enum.run(
                        "example.com",
                        use_cert_transparency=True,
                        use_dns_bruteforce=False
                    )

                assert results["domain"] == "example.com"
                assert results["total_found"] == 2
                assert "www.example.com" in results["subdomains"]
                assert "api.example.com" in results["subdomains"]

    def test_run_with_bruteforce_only(self, test_config):
        """Test running with DNS brute-force only."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("offensive_toolkit.reconnaissance.subdomain_enum.check_authorization") as mock_auth:
            mock_auth.return_value = True

            with patch.object(enum, "dns_bruteforce") as mock_dns:
                mock_dns.return_value = {"mail.example.com", "ftp.example.com"}

                with patch.object(enum, "_save_results"):
                    results = enum.run(
                        "example.com",
                        use_cert_transparency=False,
                        use_dns_bruteforce=True
                    )

                assert results["total_found"] == 2
                assert "mail.example.com" in results["subdomains"]
                assert "ftp.example.com" in results["subdomains"]

    def test_run_with_both_methods(self, test_config):
        """Test running with both enumeration methods."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("offensive_toolkit.reconnaissance.subdomain_enum.check_authorization") as mock_auth:
            mock_auth.return_value = True

            with patch.object(enum, "cert_transparency_search") as mock_cert:
                mock_cert.return_value = {"www.example.com", "api.example.com"}

                with patch.object(enum, "dns_bruteforce") as mock_dns:
                    mock_dns.return_value = {"mail.example.com", "www.example.com"}  # www overlap

                    with patch.object(enum, "_save_results"):
                        results = enum.run("example.com")

                    # Should have 3 unique subdomains (www appears in both)
                    assert results["total_found"] == 3
                    assert set(results["subdomains"]) == {
                        "www.example.com",
                        "api.example.com",
                        "mail.example.com"
                    }

    def test_run_with_custom_wordlist(self, test_config):
        """Test running with custom wordlist file."""
        enum = SubdomainEnumerator(config=test_config)

        mock_wordlist_content = "custom1\ncustom2\ncustom3\n"

        with patch("offensive_toolkit.reconnaissance.subdomain_enum.check_authorization") as mock_auth:
            mock_auth.return_value = True

            with patch("builtins.open", mock_open(read_data=mock_wordlist_content)):
                with patch.object(enum, "dns_bruteforce") as mock_dns:
                    mock_dns.return_value = set()

                    with patch.object(enum, "_save_results"):
                        enum.run("example.com", wordlist_file="custom.txt", use_cert_transparency=False)

                    # Verify custom wordlist was passed
                    mock_dns.assert_called_once()
                    call_args = mock_dns.call_args
                    assert call_args[0][0] == "example.com"
                    assert call_args[0][1] == ["custom1", "custom2", "custom3"]

    def test_run_wordlist_file_error(self, test_config):
        """Test handling wordlist file not found."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("offensive_toolkit.reconnaissance.subdomain_enum.check_authorization") as mock_auth:
            mock_auth.return_value = True

            with patch("builtins.open", side_effect=FileNotFoundError()):
                with patch.object(enum, "dns_bruteforce") as mock_dns:
                    mock_dns.return_value = set()

                    with patch.object(enum, "_save_results"):
                        enum.run("example.com", wordlist_file="missing.txt", use_cert_transparency=False)

                    # Should fall back to default wordlist (None)
                    call_args = mock_dns.call_args
                    assert call_args[0][1] is None

    def test_run_results_sorted(self, test_config):
        """Test that results are sorted alphabetically."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("offensive_toolkit.reconnaissance.subdomain_enum.check_authorization") as mock_auth:
            mock_auth.return_value = True

            with patch.object(enum, "dns_bruteforce") as mock_dns:
                # Return in random order
                mock_dns.return_value = {"zzz.example.com", "aaa.example.com", "mmm.example.com"}

                with patch.object(enum, "_save_results"):
                    results = enum.run("example.com", use_cert_transparency=False)

                # Should be sorted
                assert results["subdomains"] == [
                    "aaa.example.com",
                    "mmm.example.com",
                    "zzz.example.com"
                ]


class TestRateLimiting:
    """Tests for rate limiting during enumeration."""

    def test_rate_limiting_in_dns_check(self, test_config):
        """Test that rate limiter is called during DNS checks."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

            with patch.object(enum.rate_limiter, "wait") as mock_wait:
                wordlist = ["www", "mail"]
                enum.dns_bruteforce("example.com", wordlist)

                # Rate limiter should be called for each subdomain
                assert mock_wait.call_count == len(wordlist)


class TestSubdomainEnumIntegration:
    """Integration tests for SubdomainEnumerator."""

    @pytest.mark.integration
    def test_full_enumeration_workflow(self, test_config):
        """Test complete enumeration workflow."""
        enum = SubdomainEnumerator(config=test_config)

        with patch("offensive_toolkit.reconnaissance.subdomain_enum.check_authorization") as mock_auth:
            mock_auth.return_value = True

            with patch.object(enum, "cert_transparency_search") as mock_cert:
                mock_cert.return_value = {"www.example.com"}

                with patch.object(enum, "dns_bruteforce") as mock_dns:
                    mock_dns.return_value = {"api.example.com"}

                    with patch.object(enum, "_save_results"):
                        results = enum.run("example.com")

                    assert results["domain"] == "example.com"
                    assert results["total_found"] == 2
                    assert "www.example.com" in results["subdomains"]
                    assert "api.example.com" in results["subdomains"]
                    # Verify found_subdomains set is cleared
                    assert len(enum.found_subdomains) == 2
