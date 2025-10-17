"""
Integration tests for reconnaissance workflow.

Tests the complete reconnaissance workflow combining multiple tools.
"""

from unittest.mock import Mock, patch

import dns.resolver
import pytest

from offensive_toolkit.reconnaissance.dns_resolver import DNSResolver
from offensive_toolkit.reconnaissance.port_scanner import PortScanner
from offensive_toolkit.reconnaissance.subdomain_enum import SubdomainEnumerator
from offensive_toolkit.reconnaissance.whois_lookup import WHOISLookup


class TestReconnaissanceWorkflow:
    """Integration tests for full reconnaissance workflow."""

    @pytest.fixture
    def authorized_domain(self, test_config, authorized_targets_file):
        """Configure authorized domain for testing."""
        test_config["authorization"]["scope_file"] = authorized_targets_file
        test_config["authorization"]["require_confirmation"] = False
        return "example.com"

    def test_dns_to_port_scan_workflow(self, test_config, authorized_domain, mock_socket):
        """Test workflow: DNS resolution -> Port scanning."""
        # Step 1: DNS resolution
        dns_resolver = DNSResolver(test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_answers = [Mock(to_text=lambda: "192.0.2.1")]
            mock_resolver.resolve.return_value = mock_answers
            mock_resolver_class.return_value = mock_resolver

            dns_results = dns_resolver.run(authorized_domain, ["A"])

            # Verify DNS resolution
            assert "records" in dns_results
            assert "A" in dns_results["records"]
            assert "192.0.2.1" in dns_results["records"]["A"]

            # Step 2: Port scanning on discovered IP
            discovered_ip = dns_results["records"]["A"][0]
            port_scanner = PortScanner(test_config)

            # Add discovered IP to authorized targets
            test_config["authorization"]["authorized_targets"] = [discovered_ip]

            scan_results = port_scanner.run(discovered_ip, "80,443")

            # Verify port scan
            assert scan_results["target"] == discovered_ip
            assert scan_results["total_ports_scanned"] == 2
            assert 80 in scan_results["results"]
            assert 443 in scan_results["results"]

    def test_subdomain_to_dns_workflow(self, test_config, authorized_domain):
        """Test workflow: Subdomain enumeration -> DNS resolution."""
        # Step 1: Subdomain enumeration
        subdomain_enum = SubdomainEnumerator(test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver.timeout = 2
            mock_resolver.lifetime = 2

            # Simulate finding subdomains
            def mock_resolve(domain, record_type):
                if domain in ["www.example.com", "mail.example.com"]:
                    return [Mock()]
                raise dns.resolver.NXDOMAIN()

            mock_resolver.resolve = mock_resolve
            mock_resolver_class.return_value = mock_resolver

            # Mock certificate transparency search
            with patch("requests.get") as mock_get:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = [
                    {"name_value": "api.example.com"},
                    {"name_value": "blog.example.com"},
                ]
                mock_get.return_value = mock_response

                subdomain_results = subdomain_enum.run(
                    authorized_domain, use_cert_transparency=True, use_dns_bruteforce=True
                )

                # Verify subdomain enumeration
                assert subdomain_results["domain"] == authorized_domain
                assert subdomain_results["total_found"] > 0
                assert len(subdomain_results["subdomains"]) > 0

                # Step 2: DNS resolution for discovered subdomains
                dns_resolver = DNSResolver(test_config)
                discovered_subdomains = subdomain_results["subdomains"][:2]  # Test first 2

                for subdomain in discovered_subdomains:
                    # Mock DNS resolution
                    mock_resolver.resolve = lambda d, t: [Mock(to_text=lambda: "192.0.2.100")]
                    dns_results = dns_resolver.comprehensive_lookup(subdomain, ["A"])

                    # Verify DNS records found
                    assert isinstance(dns_results, dict)

    def test_full_reconnaissance_workflow(
        self, test_config, authorized_domain, mock_socket, tmp_path
    ):
        """Test complete reconnaissance workflow: DNS -> Subdomains -> WHOIS -> Port Scan."""
        test_config["output"]["directory"] = str(tmp_path)

        # Step 1: DNS Resolution
        print("\n[*] Step 1: DNS Resolution")
        dns_resolver = DNSResolver(test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_answers_a = [Mock(to_text=lambda: "192.0.2.1")]
            mock_answers_mx = [Mock(preference=10, exchange="mail.example.com.")]

            def mock_resolve(domain, record_type):
                if record_type == "A":
                    return mock_answers_a
                if record_type == "MX":
                    return mock_answers_mx
                raise dns.resolver.NoAnswer()

            mock_resolver.resolve = mock_resolve
            mock_resolver_class.return_value = mock_resolver

            dns_results = dns_resolver.run(authorized_domain, ["A", "MX"])
            assert "records" in dns_results
            assert "A" in dns_results["records"]

            # Step 2: Subdomain Enumeration
            print("[*] Step 2: Subdomain Enumeration")
            subdomain_enum = SubdomainEnumerator(test_config)

            # Mock DNS for subdomain checks
            mock_resolver.resolve = lambda d, t: [Mock()] if "www" in d or "mail" in d else None

            # Mock certificate transparency
            with patch("requests.get") as mock_get:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = [
                    {"name_value": "www.example.com\napi.example.com"}
                ]
                mock_get.return_value = mock_response

                subdomain_results = subdomain_enum.run(
                    authorized_domain,
                    use_cert_transparency=True,
                    use_dns_bruteforce=False,  # Skip brute-force for speed
                )

                assert subdomain_results["total_found"] > 0

                # Step 3: WHOIS Lookup
                print("[*] Step 3: WHOIS Lookup")
                whois_lookup = WHOISLookup(test_config)

                with patch("socket.socket") as mock_socket_class:
                    mock_sock = Mock()
                    mock_sock.recv.side_effect = [
                        b"Domain Name: EXAMPLE.COM\r\n",
                        b"Registrar: Example Registrar Inc.\r\n",
                        b"Creation Date: 2020-01-01T00:00:00Z\r\n",
                        b"",
                    ]
                    mock_socket_class.return_value = mock_sock

                    whois_results = whois_lookup.run(authorized_domain, parse=True)
                    assert "domain" in whois_results
                    assert "parsed" in whois_results

                    # Step 4: Port Scanning on discovered IP
                    print("[*] Step 4: Port Scanning")
                    discovered_ip = dns_results["records"]["A"][0]
                    test_config["authorization"]["authorized_targets"] = [discovered_ip]

                    port_scanner = PortScanner(test_config)
                    port_results = port_scanner.run(discovered_ip, "80,443,8080")

                    assert port_results["target"] == discovered_ip
                    assert "results" in port_results

        # Step 5: Verify all output files created
        print("[*] Step 5: Verifying output files")
        output_files = list(tmp_path.glob("*.json"))
        assert len(output_files) >= 3  # DNS, subdomain, WHOIS, port scan

        # Verify file types
        file_types = [f.name.split("_")[0] for f in output_files]
        assert "dns" in file_types or "subdomains" in file_types

    def test_parallel_dns_resolution(self, test_config, authorized_domain):
        """Test parallel DNS resolution across multiple resolvers."""
        dns_resolver = DNSResolver(test_config)
        dns_resolver.resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver.resolve.return_value = [Mock(to_text=lambda: "192.0.2.1")]
            mock_resolver_class.return_value = mock_resolver

            results = dns_resolver.resolve_multiple_resolvers(authorized_domain, "A")

            # Should have results from all resolvers
            assert len(results) >= 1
            assert all(isinstance(v, list) for v in results.values())

    def test_reconnaissance_with_rate_limiting(self, test_config, authorized_domain):
        """Test that reconnaissance respects rate limiting."""
        import time

        test_config["rate_limit"]["requests_per_second"] = 10

        subdomain_enum = SubdomainEnumerator(test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver.resolve.return_value = [Mock()]
            mock_resolver_class.return_value = mock_resolver

            start_time = time.time()

            # Test with small wordlist (5 items)
            wordlist = ["www", "mail", "ftp", "admin", "test"]
            subdomain_enum.dns_bruteforce(authorized_domain, wordlist)

            elapsed_time = time.time() - start_time

            # With 10 req/s, 5 requests should take at least 0.4 seconds
            assert elapsed_time >= 0.4

    def test_error_handling_in_workflow(self, test_config, authorized_domain):
        """Test error handling when tools fail in workflow."""
        # Test DNS resolution failure
        dns_resolver = DNSResolver(test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver.resolve.side_effect = dns.exception.Timeout()
            mock_resolver_class.return_value = mock_resolver

            # Should handle timeout gracefully
            records = dns_resolver.query_record(authorized_domain, "A")
            assert records == []

        # Test subdomain enumeration with network errors
        subdomain_enum = SubdomainEnumerator(test_config)

        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Network error")

            # Should handle error gracefully
            result = subdomain_enum.cert_transparency_search(authorized_domain)
            assert isinstance(result, set)

    def test_workflow_with_invalid_targets(self, test_config):
        """Test workflow handles invalid targets correctly."""
        # Invalid domain
        dns_resolver = DNSResolver(test_config)
        result = dns_resolver.run("invalid!@#domain", ["A"])
        assert "error" in result

        # Unauthorized target
        port_scanner = PortScanner(test_config)
        result = port_scanner.run("192.168.99.99", "80")
        assert "error" in result
        assert result["error"] == "Not authorized"


class TestReconnaissanceDataFlow:
    """Test data flow between reconnaissance tools."""

    def test_dns_results_format(self, test_config):
        """Test DNS results can be consumed by other tools."""
        dns_resolver = DNSResolver(test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver.resolve.return_value = [Mock(to_text=lambda: "192.0.2.1")]
            mock_resolver_class.return_value = mock_resolver

            test_config["authorization"]["authorized_targets"] = ["example.com"]
            results = dns_resolver.run("example.com", ["A"])

            # Verify format
            assert isinstance(results, dict)
            assert "domain" in results
            assert "records" in results
            assert isinstance(results["records"], dict)

    def test_subdomain_results_format(self, test_config):
        """Test subdomain results can be consumed by other tools."""
        subdomain_enum = SubdomainEnumerator(test_config)

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver.resolve.return_value = [Mock()]
            mock_resolver_class.return_value = mock_resolver

            with patch("requests.get") as mock_get:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = []
                mock_get.return_value = mock_response

                test_config["authorization"]["authorized_targets"] = ["example.com"]
                results = subdomain_enum.run("example.com", use_dns_bruteforce=False)

                # Verify format
                assert isinstance(results, dict)
                assert "domain" in results
                assert "subdomains" in results
                assert isinstance(results["subdomains"], list)

    def test_port_scan_results_format(self, test_config, mock_socket):
        """Test port scan results format."""
        port_scanner = PortScanner(test_config)

        test_config["authorization"]["authorized_targets"] = ["127.0.0.1"]
        test_config["authorization"]["require_confirmation"] = False

        results = port_scanner.run("127.0.0.1", "80,443")

        # Verify format
        assert isinstance(results, dict)
        assert "target" in results
        assert "results" in results
        assert isinstance(results["results"], dict)
        assert all(isinstance(k, int) for k in results["results"].keys())
