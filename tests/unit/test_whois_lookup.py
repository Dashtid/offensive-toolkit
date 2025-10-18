#!/usr/bin/env python3
"""
Tests for WHOIS Lookup

Comprehensive unit tests for WHOISLookup class covering:
- Initialization
- WHOIS server queries
- Response parsing
- TLD to server mapping
- Referral following
- Error handling
"""

import socket
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from offensive_toolkit.reconnaissance.whois_lookup import (
    WHOIS_SERVERS,
    WHOISLookup,
)


@pytest.fixture
def test_config() -> dict[str, Any]:
    """Provide test configuration."""
    return {
        "timeouts": {"connection": 10},
        "output": {"directory": "build/test_output"},
        "authorization": {
            "require_explicit": False,
            "allowed_targets": ["example.com", "test.com"],
        },
    }


@pytest.fixture
def sample_whois_response() -> str:
    """Provide sample WHOIS response."""
    return """
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://res-dom.iana.org
Updated Date: 2024-08-14T07:01:38Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2025-08-13T04:00:00Z
Registrar: RESERVED-Internet Assigned Numbers Authority
Registrar IANA ID: 376
Registrar Abuse Contact Email: abuse@iana.org
Registrar Abuse Contact Phone: +1.3108230090
Domain Status: clientDeleteProhibited
Domain Status: clientTransferProhibited
Domain Status: clientUpdateProhibited
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: signedDelegation
"""


class TestWHOISLookupInit:
    """Tests for WHOISLookup initialization."""

    def test_init_with_config(self, test_config):
        """Test initialization with custom config."""
        whois = WHOISLookup(config=test_config)

        assert whois.config == test_config

    def test_init_without_config(self):
        """Test initialization without config (uses defaults)."""
        with patch("offensive_toolkit.reconnaissance.whois_lookup.load_config") as mock_load:
            mock_load.return_value = {"timeouts": {"connection": 10}}

            whois = WHOISLookup()

            assert whois.config is not None
            mock_load.assert_called_once()

    def test_whois_servers_populated(self):
        """Test WHOIS servers dictionary is populated."""
        assert len(WHOIS_SERVERS) > 0
        assert WHOIS_SERVERS["com"] == "whois.verisign-grs.com"
        assert WHOIS_SERVERS["org"] == "whois.pir.org"
        assert WHOIS_SERVERS["net"] == "whois.verisign-grs.com"


class TestQueryWhoisServer:
    """Tests for query_whois_server method."""

    def test_query_successful(self, test_config):
        """Test successful WHOIS query."""
        whois = WHOISLookup(config=test_config)

        mock_response = b"Domain Name: EXAMPLE.COM\nRegistrar: Test Registrar\n"

        with patch("socket.socket") as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.recv.side_effect = [mock_response, b""]  # Second call returns empty

            result = whois.query_whois_server("example.com")

            assert "Domain Name: EXAMPLE.COM" in result
            assert "Registrar: Test Registrar" in result
            mock_sock.connect.assert_called_once_with(("whois.verisign-grs.com", 43))
            mock_sock.send.assert_called_once()
            mock_sock.close.assert_called_once()

    def test_query_with_custom_server(self, test_config):
        """Test query with custom WHOIS server."""
        whois = WHOISLookup(config=test_config)

        with patch("socket.socket") as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.recv.side_effect = [b"Test response", b""]

            whois.query_whois_server("example.org", whois_server="whois.custom.com")

            mock_sock.connect.assert_called_once_with(("whois.custom.com", 43))

    def test_query_timeout(self, test_config):
        """Test handling query timeout."""
        whois = WHOISLookup(config=test_config)

        with patch("socket.socket") as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.connect.side_effect = TimeoutError()

            result = whois.query_whois_server("example.com")

            assert result == ""

    def test_query_connection_error(self, test_config):
        """Test handling connection errors."""
        whois = WHOISLookup(config=test_config)

        with patch("socket.socket") as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.connect.side_effect = socket.error("Connection refused")

            result = whois.query_whois_server("invalid.example")

            assert result == ""

    def test_query_follows_referral(self, test_config):
        """Test following WHOIS server referral."""
        whois = WHOISLookup(config=test_config)

        # First response contains referral
        referral_response = b"Registrar WHOIS Server: whois.registrar.com\n"
        # Second response is final
        final_response = b"Domain Name: EXAMPLE.COM\nRegistrar: Final Registrar\n"

        with patch.object(whois, "query_whois_server", wraps=whois.query_whois_server) as mock_query:
            with patch("socket.socket") as mock_socket_class:
                mock_sock = Mock()
                mock_socket_class.return_value = mock_sock

                # First call returns referral, second call returns final response
                mock_sock.recv.side_effect = [
                    referral_response, b"",  # First query
                    final_response, b""       # Referral query
                ]

                result = whois.query_whois_server("example.com")

                # Should have been called twice (initial + referral)
                assert mock_query.call_count == 2

    def test_query_tld_mapping(self, test_config):
        """Test TLD to WHOIS server mapping."""
        whois = WHOISLookup(config=test_config)

        with patch("socket.socket") as mock_socket_class:
            mock_sock = Mock()
            mock_socket_class.return_value = mock_sock
            mock_sock.recv.return_value = b""

            # Test .com domain
            whois.query_whois_server("test.com")
            mock_sock.connect.assert_called_with(("whois.verisign-grs.com", 43))

            # Test .org domain
            whois.query_whois_server("test.org")
            mock_sock.connect.assert_called_with(("whois.pir.org", 43))


class TestParseWhois:
    """Tests for parse_whois method."""

    def test_parse_domain_name(self, test_config, sample_whois_response):
        """Test parsing domain name."""
        whois = WHOISLookup(config=test_config)

        result = whois.parse_whois(sample_whois_response)

        assert result["domain_name"] == "EXAMPLE.COM"

    def test_parse_registrar(self, test_config, sample_whois_response):
        """Test parsing registrar."""
        whois = WHOISLookup(config=test_config)

        result = whois.parse_whois(sample_whois_response)

        assert result["registrar"] == "RESERVED-Internet Assigned Numbers Authority"

    def test_parse_dates(self, test_config, sample_whois_response):
        """Test parsing dates."""
        whois = WHOISLookup(config=test_config)

        result = whois.parse_whois(sample_whois_response)

        assert "1995-08-14" in result["creation_date"]
        assert "2025-08-13" in result["expiration_date"]
        assert "2024-08-14" in result["updated_date"]

    def test_parse_name_servers(self, test_config, sample_whois_response):
        """Test parsing name servers."""
        whois = WHOISLookup(config=test_config)

        result = whois.parse_whois(sample_whois_response)

        assert len(result["name_servers"]) == 2
        assert "A.IANA-SERVERS.NET" in result["name_servers"]
        assert "B.IANA-SERVERS.NET" in result["name_servers"]

    def test_parse_status(self, test_config, sample_whois_response):
        """Test parsing domain status."""
        whois = WHOISLookup(config=test_config)

        result = whois.parse_whois(sample_whois_response)

        assert len(result["status"]) == 3
        assert "clientDeleteProhibited" in result["status"]
        assert "clientTransferProhibited" in result["status"]
        assert "clientUpdateProhibited" in result["status"]

    def test_parse_dnssec(self, test_config, sample_whois_response):
        """Test parsing DNSSEC status."""
        whois = WHOISLookup(config=test_config)

        result = whois.parse_whois(sample_whois_response)

        assert result["dnssec"] == "signedDelegation"

    def test_parse_empty_response(self, test_config):
        """Test parsing empty WHOIS response."""
        whois = WHOISLookup(config=test_config)

        result = whois.parse_whois("")

        assert result["domain_name"] is None
        assert result["registrar"] is None
        assert len(result["name_servers"]) == 0

    def test_parse_skips_comments(self, test_config):
        """Test that parser skips comments."""
        whois = WHOISLookup(config=test_config)

        whois_text = """
% This is a comment
# Another comment
Domain Name: TEST.COM
% More comments
Registrar: Test Registrar
"""

        result = whois.parse_whois(whois_text)

        assert result["domain_name"] == "TEST.COM"
        assert result["registrar"] == "Test Registrar"


class TestWHOISLookupIntegration:
    """Integration tests for WHOISLookup."""

    @pytest.mark.integration
    def test_full_lookup_workflow(self, test_config, sample_whois_response):
        """Test complete WHOIS lookup workflow."""
        whois = WHOISLookup(config=test_config)

        with patch("offensive_toolkit.reconnaissance.whois_lookup.check_authorization") as mock_auth:
            mock_auth.return_value = True

            with patch.object(whois, "query_whois_server") as mock_query:
                mock_query.return_value = sample_whois_response

                with patch.object(whois, "_save_results"):
                    results = whois.run("example.com", parse=True)

                assert results["domain"] == "example.com"
                assert "raw" in results
                assert "parsed" in results
                assert results["parsed"]["domain_name"] == "EXAMPLE.COM"
