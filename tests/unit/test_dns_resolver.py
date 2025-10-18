#!/usr/bin/env python3
"""
Tests for DNS Resolver

Comprehensive unit tests for DNSResolver class covering:
- Initialization
- Single record queries (A, AAAA, MX, TXT, SOA, NS, CNAME, PTR)
- Multiple resolver comparison
- Comprehensive lookups
- Reverse DNS lookups
- Error handling
"""

from typing import Any
from unittest.mock import MagicMock, Mock, patch

import dns.exception
import dns.resolver
import pytest

from offensive_toolkit.reconnaissance.dns_resolver import (
    DEFAULT_RESOLVERS,
    RECORD_TYPES,
    DNSResolver,
)


@pytest.fixture
def test_config() -> dict[str, Any]:
    """Provide test configuration."""
    return {
        "timeouts": {"connection": 5},
        "output": {"directory": "test_output"},
        "authorization": {
            "require_explicit": False,
            "allowed_targets": ["example.com", "test.com"],
        },
    }


class TestDNSResolverInit:
    """Tests for DNSResolver initialization."""

    def test_init_with_config(self, test_config):
        """Test initialization with custom config."""
        resolver = DNSResolver(config=test_config)

        assert resolver.config == test_config
        assert resolver.resolvers == DEFAULT_RESOLVERS

    def test_init_without_config(self):
        """Test initialization without config (uses defaults)."""
        with patch("offensive_toolkit.reconnaissance.dns_resolver.load_config") as mock_load:
            mock_load.return_value = {"timeouts": {"connection": 10}}

            resolver = DNSResolver()

            assert resolver.config is not None
            assert resolver.resolvers == DEFAULT_RESOLVERS
            mock_load.assert_called_once()

    def test_default_resolvers_populated(self):
        """Test default resolvers list is populated."""
        assert len(DEFAULT_RESOLVERS) > 0
        assert "8.8.8.8" in DEFAULT_RESOLVERS  # Google DNS
        assert "1.1.1.1" in DEFAULT_RESOLVERS  # Cloudflare DNS

    def test_record_types_defined(self):
        """Test DNS record types are defined."""
        assert "A" in RECORD_TYPES
        assert "AAAA" in RECORD_TYPES
        assert "MX" in RECORD_TYPES
        assert "TXT" in RECORD_TYPES
        assert "NS" in RECORD_TYPES


class TestQueryRecord:
    """Tests for query_record method."""

    def test_query_a_record(self, test_config):
        """Test querying A records."""
        resolver = DNSResolver(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver

            # Mock DNS response with proper RData objects
            mock_rdata = Mock()
            mock_rdata.__str__ = Mock(return_value="93.184.216.34")

            mock_answer = [mock_rdata]
            mock_resolver.resolve.return_value = mock_answer

            results = resolver.query_record("example.com", "A")

            assert len(results) == 1
            assert "93.184.216.34" in results

    def test_query_aaaa_record(self, test_config):
        """Test querying AAAA (IPv6) records."""
        resolver = DNSResolver(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver

            mock_rdata = Mock()
            mock_rdata.__str__ = Mock(return_value="2606:2800:220:1:248:1893:25c8:1946")

            mock_answer = [mock_rdata]
            mock_resolver.resolve.return_value = mock_answer

            results = resolver.query_record("example.com", "AAAA")

            assert len(results) == 1
            assert "2606:2800:220:1:248:1893:25c8:1946" in results

    def test_query_mx_record(self, test_config):
        """Test querying MX (mail exchange) records."""
        resolver = DNSResolver(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver

            # MX record has preference and exchange
            mx_record = Mock()
            mx_record.preference = 10
            mx_record.exchange = "mail.example.com"

            mock_answer = Mock()
            mock_answer.__iter__ = lambda self: iter([mx_record])
            mock_resolver.resolve.return_value = mock_answer

            results = resolver.query_record("example.com", "MX")

            assert len(results) == 1
            assert "10 mail.example.com" in results[0]

    def test_query_txt_record(self, test_config):
        """Test querying TXT records."""
        resolver = DNSResolver(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver

            mock_rdata = Mock()
            mock_rdata.__str__ = Mock(return_value='"v=spf1 include:_spf.example.com ~all"')

            mock_answer = [mock_rdata]
            mock_resolver.resolve.return_value = mock_answer

            results = resolver.query_record("example.com", "TXT")

            assert len(results) == 1
            assert "v=spf1" in results[0]

    def test_query_soa_record(self, test_config):
        """Test querying SOA (start of authority) records."""
        resolver = DNSResolver(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver

            soa_record = Mock()
            soa_record.mname = "ns1.example.com"
            soa_record.rname = "admin.example.com"

            mock_answer = Mock()
            mock_answer.__iter__ = lambda self: iter([soa_record])
            mock_resolver.resolve.return_value = mock_answer

            results = resolver.query_record("example.com", "SOA")

            assert len(results) == 1
            assert "ns1.example.com" in results[0]
            assert "admin.example.com" in results[0]

    def test_query_with_specific_resolver(self, test_config):
        """Test querying with specific resolver IP."""
        resolver = DNSResolver(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver

            mock_rdata = Mock()
            mock_rdata.__str__ = Mock(return_value="1.2.3.4")

            mock_answer = [mock_rdata]
            mock_resolver.resolve.return_value = mock_answer

            results = resolver.query_record("example.com", "A", resolver_ip="8.8.8.8")

            # Verify resolver IP was set
            assert mock_resolver.nameservers == ["8.8.8.8"]
            assert len(results) == 1

    def test_query_nxdomain(self, test_config):
        """Test handling non-existent domain."""
        resolver = DNSResolver(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

            results = resolver.query_record("nonexistent.example.com", "A")

            assert results == []

    def test_query_no_answer(self, test_config):
        """Test handling no answer for record type."""
        resolver = DNSResolver(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()

            results = resolver.query_record("example.com", "AAAA")

            assert results == []

    def test_query_timeout(self, test_config):
        """Test handling DNS timeout."""
        resolver = DNSResolver(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.exception.Timeout()

            results = resolver.query_record("slow.example.com", "A")

            assert results == []

    def test_query_generic_exception(self, test_config):
        """Test handling generic DNS exception."""
        resolver = DNSResolver(config=test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = Exception("DNS error")

            results = resolver.query_record("error.example.com", "A")

            assert results == []


class TestResolveMultipleResolvers:
    """Tests for resolve_multiple_resolvers method."""

    def test_compare_across_resolvers(self, test_config):
        """Test comparing DNS results across multiple resolvers."""
        resolver = DNSResolver(config=test_config)
        # Use only 2 resolvers for testing
        resolver.resolvers = ["8.8.8.8", "1.1.1.1"]

        with patch.object(resolver, "query_record") as mock_query:
            mock_query.side_effect = [
                ["93.184.216.34"],  # Google DNS result
                ["93.184.216.34"],  # Cloudflare DNS result
            ]

            results = resolver.resolve_multiple_resolvers("example.com", "A")

            assert "8.8.8.8" in results
            assert "1.1.1.1" in results
            assert results["8.8.8.8"] == ["93.184.216.34"]
            assert results["1.1.1.1"] == ["93.184.216.34"]

    def test_some_resolvers_fail(self, test_config):
        """Test when some resolvers return no results."""
        resolver = DNSResolver(config=test_config)
        resolver.resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

        with patch.object(resolver, "query_record") as mock_query:
            # First and third succeed, second fails
            mock_query.side_effect = [
                ["1.2.3.4"],
                [],  # No results
                ["1.2.3.4"],
            ]

            results = resolver.resolve_multiple_resolvers("example.com", "A")

            assert len(results) == 2  # Only successful resolvers
            assert "8.8.8.8" in results
            assert "9.9.9.9" in results
            assert "1.1.1.1" not in results


class TestComprehensiveLookup:
    """Tests for comprehensive_lookup method."""

    def test_lookup_all_default_types(self, test_config):
        """Test comprehensive lookup with default record types."""
        resolver = DNSResolver(config=test_config)

        with patch.object(resolver, "query_record") as mock_query:
            # Return results for A and MX only
            def query_side_effect(domain, record_type):
                if record_type == "A":
                    return ["93.184.216.34"]
                elif record_type == "MX":
                    return ["10 mail.example.com"]
                return []

            mock_query.side_effect = query_side_effect

            results = resolver.comprehensive_lookup("example.com")

            assert "A" in results
            assert "MX" in results
            assert len(results["A"]) == 1
            assert len(results["MX"]) == 1

    def test_lookup_specific_types(self, test_config):
        """Test comprehensive lookup with specific record types."""
        resolver = DNSResolver(config=test_config)

        with patch.object(resolver, "query_record") as mock_query:
            mock_query.side_effect = [
                ["93.184.216.34"],  # A record
                ['"v=spf1 ~all"'],  # TXT record
            ]

            results = resolver.comprehensive_lookup("example.com", record_types=["A", "TXT"])

            assert "A" in results
            assert "TXT" in results
            assert mock_query.call_count == 2

    def test_lookup_no_results(self, test_config):
        """Test comprehensive lookup when no records found."""
        resolver = DNSResolver(config=test_config)

        with patch.object(resolver, "query_record") as mock_query:
            mock_query.return_value = []

            results = resolver.comprehensive_lookup("nonexistent.example.com")

            assert results == {}


class TestReverseLookup:
    """Tests for reverse_lookup method."""

    def test_reverse_lookup_success(self, test_config):
        """Test successful reverse DNS lookup."""
        resolver = DNSResolver(config=test_config)

        with patch("socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("example.com", [], ["93.184.216.34"])

            hostname = resolver.reverse_lookup("93.184.216.34")

            assert hostname == "example.com"
            mock_gethostbyaddr.assert_called_once_with("93.184.216.34")

    def test_reverse_lookup_ipv6(self, test_config):
        """Test reverse lookup for IPv6 address."""
        resolver = DNSResolver(config=test_config)

        with patch("socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("ipv6.example.com", [], ["2606:2800:220:1:248:1893:25c8:1946"])

            hostname = resolver.reverse_lookup("2606:2800:220:1:248:1893:25c8:1946")

            assert hostname == "ipv6.example.com"

    def test_reverse_lookup_fails(self, test_config):
        """Test reverse lookup failure."""
        resolver = DNSResolver(config=test_config)

        with patch("socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.side_effect = Exception("No reverse DNS")

            hostname = resolver.reverse_lookup("1.2.3.4")

            assert hostname is None

    def test_reverse_lookup_invalid_ip(self, test_config):
        """Test reverse lookup with invalid IP."""
        resolver = DNSResolver(config=test_config)

        hostname = resolver.reverse_lookup("not-an-ip")

        assert hostname is None


class TestDNSResolverIntegration:
    """Integration tests for DNSResolver."""

    @pytest.mark.integration
    def test_full_resolution_workflow(self, test_config):
        """Test complete DNS resolution workflow."""
        resolver = DNSResolver(config=test_config)

        with patch("offensive_toolkit.reconnaissance.dns_resolver.check_authorization") as mock_auth:
            mock_auth.return_value = True

            with patch.object(resolver, "comprehensive_lookup") as mock_lookup:
                mock_lookup.return_value = {
                    "A": ["93.184.216.34"],
                    "MX": ["10 mail.example.com"],
                    "NS": ["ns1.example.com", "ns2.example.com"],
                }

                with patch.object(resolver, "_save_results"):
                    results = resolver.run("example.com")

                assert "domain" in results
                assert results["domain"] == "example.com"
                assert "records" in results
                assert "A" in results["records"]
                assert "MX" in results["records"]
                assert "NS" in results["records"]

    @pytest.mark.integration
    def test_resolver_comparison_mode(self, test_config):
        """Test resolver comparison mode."""
        resolver = DNSResolver(config=test_config)

        with patch("offensive_toolkit.reconnaissance.dns_resolver.check_authorization") as mock_auth:
            mock_auth.return_value = True

            with patch.object(resolver, "resolve_multiple_resolvers") as mock_multi:
                mock_multi.return_value = {
                    "8.8.8.8": ["93.184.216.34"],
                    "1.1.1.1": ["93.184.216.34"],
                }

                with patch.object(resolver, "_save_results"):
                    results = resolver.run("example.com", record_types=["A"], compare_resolvers=True)

                assert results["records"]["A"]["8.8.8.8"] == ["93.184.216.34"]
                assert results["records"]["A"]["1.1.1.1"] == ["93.184.216.34"]
