"""
Integration tests for web security workflow.

Tests the complete web security testing workflow combining multiple tools.
"""

import pytest
from unittest.mock import Mock, patch
import requests

from web_security.directory_bruteforcer import DirectoryBruteforcer
from web_security.sql_injection import SQLInjectionScanner
from web_security.xss_scanner import XSSScanner


class TestWebSecurityWorkflow:
    """Integration tests for full web security testing workflow."""

    @pytest.fixture
    def authorized_url(self, test_config, authorized_targets_file):
        """Configure authorized URL for testing."""
        test_config["authorization"]["scope_file"] = authorized_targets_file
        test_config["authorization"]["require_confirmation"] = False
        # Add URL to authorized targets
        test_config["authorization"]["authorized_targets"] = ["http://example.com"]
        return "http://example.com"

    def test_directory_to_vulnerability_scan_workflow(self, test_config, authorized_url):
        """Test workflow: Directory brute-force -> Vulnerability scanning on found pages."""
        # Step 1: Directory brute-forcing
        bruteforcer = DirectoryBruteforcer(test_config)

        with patch("requests.Session.get") as mock_get:
            # Simulate finding admin and login pages
            def mock_response(*args, **kwargs):
                response = Mock()
                url = args[0] if args else kwargs.get("url", "")

                if "/admin" in url or "/login" in url:
                    response.status_code = 200
                    response.content = b"<html><body><form><input name='username'></form></body></html>"
                    response.headers = {"Content-Type": "text/html"}
                else:
                    response.status_code = 404
                    response.content = b"Not Found"
                    response.headers = {}

                return response

            mock_get.side_effect = mock_response

            dir_results = bruteforcer.run(authorized_url, wordlist=["admin", "login", "test"])

            # Verify directory discovery
            assert dir_results["total_found"] >= 2
            assert len(dir_results["results"]) >= 2

            # Step 2: SQL injection scan on discovered pages
            sqli_scanner = SQLInjectionScanner(test_config)

            for found_page in dir_results["results"]:
                test_url = found_page["url"]

                # Mock SQL injection testing
                with patch("requests.Session.get") as mock_sqli_get:
                    sqli_response = Mock()
                    sqli_response.status_code = 200
                    sqli_response.text = "MySQL syntax error"
                    mock_sqli_get.return_value = sqli_response

                    sqli_results = sqli_scanner.run(
                        f"{test_url}?id=1",
                        test_all_types=False
                    )

                    # Should complete without errors
                    assert "error" not in sqli_results
                    assert "vulnerabilities_found" in sqli_results

    def test_complete_web_security_workflow(self, test_config, authorized_url, tmp_path):
        """Test complete workflow: Discovery -> SQLi -> XSS scanning."""
        test_config["output"]["directory"] = str(tmp_path)

        # Step 1: Directory Discovery
        print("\n[*] Step 1: Directory Discovery")
        bruteforcer = DirectoryBruteforcer(test_config)

        with patch("requests.Session.get") as mock_get:
            def dir_mock_response(*args, **kwargs):
                response = Mock()
                url = args[0] if args else kwargs.get("url", "")

                if any(path in url for path in ["/search", "/comment", "/profile"]):
                    response.status_code = 200
                    response.content = b"<html>Page content</html>"
                    response.headers = {"Content-Type": "text/html"}
                else:
                    response.status_code = 404
                    response.content = b"Not Found"
                    response.headers = {}

                return response

            mock_get.side_effect = dir_mock_response

            dir_results = bruteforcer.run(
                authorized_url,
                wordlist=["search", "comment", "profile", "api"]
            )

            assert dir_results["total_found"] >= 2

            # Step 2: SQL Injection Scanning
            print("[*] Step 2: SQL Injection Scanning")
            sqli_scanner = SQLInjectionScanner(test_config)
            sqli_vulnerabilities = []

            for found_page in dir_results["results"][:2]:  # Test first 2 pages
                test_url = f"{found_page['url']}?id=1"

                with patch("requests.Session.get") as mock_sqli_get:
                    sqli_response = Mock()
                    sqli_response.status_code = 200
                    sqli_response.text = "You have an error in your SQL syntax"
                    mock_sqli_get.return_value = sqli_response

                    sqli_results = sqli_scanner.run(test_url, params=["id"])

                    if sqli_results.get("vulnerabilities_found", 0) > 0:
                        sqli_vulnerabilities.extend(sqli_results["vulnerabilities"])

            # Step 3: XSS Scanning
            print("[*] Step 3: XSS Scanning")
            xss_scanner = XSSScanner(test_config)
            xss_vulnerabilities = []

            for found_page in dir_results["results"][:2]:
                test_url = f"{found_page['url']}?q=test"

                with patch("requests.Session.get") as mock_xss_get:
                    def xss_mock_response(*args, **kwargs):
                        url = args[0] if args else kwargs.get("url", "")
                        response = Mock()
                        response.status_code = 200

                        # Reflect payload in response
                        if "q=" in url:
                            payload = url.split("q=")[1].split("&")[0]
                            response.text = f"<html><body>Search results for: {payload}</body></html>"
                        else:
                            response.text = "<html><body>Page content</body></html>"

                        return response

                    mock_xss_get.side_effect = xss_mock_response

                    xss_results = xss_scanner.run(test_url, params=["q"], test_dom=False)

                    if xss_results.get("vulnerabilities_found", 0) > 0:
                        xss_vulnerabilities.extend(xss_results["vulnerabilities"])

            # Step 4: Verify all scans completed
            print("[*] Step 4: Verifying results")
            assert dir_results["total_found"] > 0
            assert "vulnerabilities_found" in sqli_results
            assert "vulnerabilities_found" in xss_results

            # Step 5: Verify output files
            output_files = list(tmp_path.glob("*.json"))
            assert len(output_files) >= 2  # At least some results saved

    def test_sql_injection_deep_scan(self, test_config, authorized_url):
        """Test comprehensive SQL injection scanning with all injection types."""
        sqli_scanner = SQLInjectionScanner(test_config)

        test_url = f"{authorized_url}/login?username=admin"

        with patch("requests.Session.get") as mock_get, \
             patch("requests.Session.post") as mock_post:

            # Mock responses for different injection types
            def mock_response(*args, **kwargs):
                response = Mock()
                response.status_code = 200
                url_or_data = args[0] if args else kwargs.get("url", "")

                # Simulate error-based SQLi
                if "'" in str(url_or_data):
                    response.text = "MySQL syntax error at line 1"
                else:
                    response.text = "<html>Login page</html>"

                return response

            mock_get.side_effect = mock_response
            mock_post.side_effect = mock_response

            # Test all injection types
            results = sqli_scanner.run(
                test_url,
                params=["username"],
                test_all_types=True
            )

            # Verify all injection types were tested
            assert "injection_types" in results
            assert len(results["injection_types"]) == 4  # All InjectionType enums

    def test_xss_with_dom_analysis(self, test_config, authorized_url):
        """Test XSS scanning with DOM-based XSS detection."""
        xss_scanner = XSSScanner(test_config)

        test_url = f"{authorized_url}/profile"

        with patch("requests.Session.get") as mock_get:
            # Mock response with DOM XSS pattern
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = """
            <html>
            <script>
                var search = location.search;
                document.write(search);
            </script>
            </html>
            """
            mock_get.return_value = mock_response

            results = xss_scanner.run(test_url, test_dom=True)

            # Should detect DOM-based XSS pattern
            assert "vulnerabilities_found" in results

            if results["vulnerabilities_found"] > 0:
                dom_vulns = [v for v in results["vulnerabilities"] if v["type"] == "dom-based"]
                assert len(dom_vulns) > 0

    def test_parallel_vulnerability_scanning(self, test_config, authorized_url):
        """Test scanning multiple pages in parallel."""
        import time

        test_urls = [
            f"{authorized_url}/page1?id=1",
            f"{authorized_url}/page2?id=1",
            f"{authorized_url}/page3?id=1",
        ]

        sqli_scanner = SQLInjectionScanner(test_config)
        test_config["rate_limit"]["requests_per_second"] = 10

        with patch("requests.Session.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "Normal response"
            mock_get.return_value = mock_response

            start_time = time.time()

            results = []
            for url in test_urls:
                result = sqli_scanner.run(url, params=["id"], test_all_types=False)
                results.append(result)

            elapsed_time = time.time() - start_time

            # Verify all scans completed
            assert len(results) == 3
            assert all("error" not in r for r in results)

            # Rate limiting should be applied
            assert elapsed_time >= 0.3  # Minimum time with rate limiting

    def test_error_handling_in_workflow(self, test_config, authorized_url):
        """Test error handling when scans fail."""
        # Test network error handling
        sqli_scanner = SQLInjectionScanner(test_config)

        with patch("requests.Session.get") as mock_get:
            mock_get.side_effect = requests.exceptions.ConnectionError("Network error")

            results = sqli_scanner.run(f"{authorized_url}?id=1", params=["id"])

            # Should handle error gracefully
            assert "vulnerabilities_found" in results

        # Test timeout handling
        xss_scanner = XSSScanner(test_config)

        with patch("requests.Session.get") as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout("Request timeout")

            results = xss_scanner.run(f"{authorized_url}?q=test", params=["q"])

            # Should handle timeout gracefully
            assert "vulnerabilities_found" in results

    def test_workflow_with_invalid_targets(self, test_config):
        """Test workflow handles invalid targets correctly."""
        # Invalid URL
        sqli_scanner = SQLInjectionScanner(test_config)
        result = sqli_scanner.run("not-a-valid-url", params=["id"])
        assert "error" in result

        # Unauthorized target
        xss_scanner = XSSScanner(test_config)
        result = xss_scanner.run("http://unauthorized-site.com?q=test")
        assert "error" in result
        assert result["error"] == "Not authorized"


class TestWebSecurityDataFlow:
    """Test data flow between web security tools."""

    def test_directory_results_format(self, test_config):
        """Test directory bruteforce results format."""
        bruteforcer = DirectoryBruteforcer(test_config)

        with patch("requests.Session.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.content = b"Content"
            mock_response.headers = {}
            mock_get.return_value = mock_response

            test_config["authorization"]["authorized_targets"] = ["http://example.com"]
            results = bruteforcer.run("http://example.com", wordlist=["admin"])

            # Verify format
            assert isinstance(results, dict)
            assert "url" in results
            assert "results" in results
            assert isinstance(results["results"], list)

    def test_sqli_results_format(self, test_config):
        """Test SQL injection results format."""
        sqli_scanner = SQLInjectionScanner(test_config)

        with patch("requests.Session.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "Response"
            mock_get.return_value = mock_response

            test_config["authorization"]["authorized_targets"] = ["http://example.com"]
            results = sqli_scanner.run("http://example.com?id=1", params=["id"])

            # Verify format
            assert isinstance(results, dict)
            assert "url" in results
            assert "vulnerabilities_found" in results
            assert "vulnerabilities" in results
            assert isinstance(results["vulnerabilities"], list)

    def test_xss_results_format(self, test_config):
        """Test XSS scanner results format."""
        xss_scanner = XSSScanner(test_config)

        with patch("requests.Session.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "<html>Response</html>"
            mock_get.return_value = mock_response

            test_config["authorization"]["authorized_targets"] = ["http://example.com"]
            results = xss_scanner.run("http://example.com?q=test", params=["q"])

            # Verify format
            assert isinstance(results, dict)
            assert "url" in results
            assert "vulnerabilities_found" in results
            assert "vulnerabilities" in results
            assert isinstance(results["vulnerabilities"], list)

    def test_vulnerability_details_format(self, test_config):
        """Test vulnerability details structure."""
        sqli_scanner = SQLInjectionScanner(test_config)

        with patch("requests.Session.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "MySQL syntax error"
            mock_get.return_value = mock_response

            test_config["authorization"]["authorized_targets"] = ["http://example.com"]
            results = sqli_scanner.run("http://example.com?id=1", params=["id"])

            # If vulnerabilities found, check format
            if results["vulnerabilities_found"] > 0:
                vuln = results["vulnerabilities"][0]

                # Required fields
                assert "type" in vuln
                assert "parameter" in vuln
                assert "payload" in vuln
                assert "evidence" in vuln
                assert "confidence" in vuln

                # Confidence levels
                assert vuln["confidence"] in ["low", "medium", "high"]


class TestWebSecurityReporting:
    """Test reporting and result aggregation."""

    def test_aggregate_scan_results(self, test_config, tmp_path):
        """Test aggregating results from multiple scans."""
        test_config["output"]["directory"] = str(tmp_path)
        test_config["authorization"]["authorized_targets"] = ["http://example.com"]

        # Run multiple scans
        bruteforcer = DirectoryBruteforcer(test_config)
        sqli_scanner = SQLInjectionScanner(test_config)
        xss_scanner = XSSScanner(test_config)

        with patch("requests.Session.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.content = b"Content"
            mock_response.text = "<html>Content</html>"
            mock_response.headers = {}
            mock_get.return_value = mock_response

            # Run scans
            dir_results = bruteforcer.run("http://example.com", wordlist=["admin"])
            sqli_results = sqli_scanner.run("http://example.com?id=1", params=["id"])
            xss_results = xss_scanner.run("http://example.com?q=test", params=["q"])

            # Verify all scans saved results
            output_files = list(tmp_path.glob("*.json"))
            assert len(output_files) >= 2

            # Aggregate vulnerability counts
            total_vulns = (
                sqli_results.get("vulnerabilities_found", 0) +
                xss_results.get("vulnerabilities_found", 0)
            )

            assert isinstance(total_vulns, int)
            assert total_vulns >= 0
