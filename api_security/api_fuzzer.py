"""
OWASP API Security Top 10 Fuzzer

Comprehensive API security testing tool based on OWASP API Security Top 10 2023.
Tests for BOLA, Broken Authentication, Excessive Data Exposure, SSRF, and more.

OWASP API Security Top 10 2023:
1. API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
2. API2:2023 - Broken Authentication
3. API3:2023 - Broken Object Property Level Authorization
4. API4:2023 - Unrestricted Resource Consumption
5. API5:2023 - Broken Function Level Authorization (BFLA)
6. API6:2023 - Unrestricted Access to Sensitive Business Flows
7. API7:2023 - Server Side Request Forgery (SSRF)
8. API8:2023 - Security Misconfiguration
9. API9:2023 - Improper Inventory Management
10. API10:2023 - Unsafe Consumption of APIs

MITRE ATT&CK Mapping:
- T1190: Exploit Public-Facing Application
- T1212: Exploitation for Credential Access
- T1557: Adversary-in-the-Middle

Author: David Dashti
License: Educational/Research Use Only
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

# Configure logging
logger = logging.getLogger(__name__)


class APIFuzzer:
    """
    OWASP API Security Top 10 fuzzer for comprehensive API testing.

    Features:
    - BOLA/IDOR detection (API1:2023)
    - Broken authentication testing (API2:2023)
    - Excessive data exposure detection (API3:2023)
    - Rate limiting testing (API4:2023)
    - BFLA detection (API5:2023)
    - SSRF testing (API7:2023)
    - Security misconfiguration detection (API8:2023)
    """

    def __init__(self, base_url: str, headers: dict[str, str] | None = None):
        """
        Initialize API fuzzer.

        Args:
            base_url: Base URL of the API
            headers: Default headers to include in all requests
        """
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.session = requests.Session()
        self.session.headers.update(self.headers)

        self.findings = {
            "scan_metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "scanner": "APIFuzzer",
                "target_url": self.base_url,
            },
            "endpoints_tested": [],
            "bola": [],
            "broken_auth": [],
            "data_exposure": [],
            "rate_limiting": [],
            "bfla": [],
            "ssrf": [],
            "misconfig": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

        logger.info(f"[+] API fuzzer initialized for {self.base_url}")

    def _add_finding(self, category: str, finding: dict[str, Any]) -> None:
        """Add finding and update severity counts."""
        self.findings[category].append(finding)
        severity = finding.get("severity", "info")
        self.findings["summary"][severity] = self.findings["summary"].get(severity, 0) + 1

    def _make_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        timeout: int = 10,
    ) -> requests.Response | None:
        """Make HTTP request with error handling."""
        url = urljoin(self.base_url, path)

        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json_data,
                timeout=timeout,
                allow_redirects=False,
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error for {method} {url}: {e}")
            return None

    def test_bola(
        self, endpoint: str, id_param: str = "id", test_ids: list[int] | None = None
    ) -> None:
        """
        Test for Broken Object Level Authorization (BOLA/IDOR) - API1:2023.

        Tests if the API allows accessing resources by manipulating object IDs
        without proper authorization checks.

        Args:
            endpoint: API endpoint with {id} placeholder (e.g., /api/users/{id})
            id_param: Name of the ID parameter
            test_ids: List of IDs to test (default: 1-10)
        """
        logger.info(f"[*] Testing BOLA on {endpoint}")

        if test_ids is None:
            test_ids = list(range(1, 11))

        baseline_responses = {}

        for test_id in test_ids:
            test_endpoint = endpoint.replace(f"{{{id_param}}}", str(test_id))

            # Test without authentication
            response_no_auth = self._make_request("GET", test_endpoint, headers={})

            # Test with authentication (if headers provided)
            response_auth = self._make_request("GET", test_endpoint)

            # Check if no auth returns data
            if response_no_auth and response_no_auth.status_code == 200:
                try:
                    data = response_no_auth.json()
                    if data and isinstance(data, dict):
                        self._add_finding(
                            "bola",
                            {
                                "type": "bola_no_auth_required",
                                "endpoint": test_endpoint,
                                "description": f"Endpoint {test_endpoint} returns data without authentication",
                                "severity": "critical",
                                "owasp": "API1:2023",
                                "recommendation": "Implement proper authentication and authorization checks",
                                "mitre": "T1190",
                            },
                        )
                except (json.JSONDecodeError, ValueError):
                    pass

            # Store baseline response
            if response_auth and response_auth.status_code == 200:
                baseline_responses[test_id] = {
                    "status": response_auth.status_code,
                    "content_length": len(response_auth.content),
                }

        # Test horizontal privilege escalation
        if len(baseline_responses) > 1:
            # Check if all IDs return similar response sizes (indicating no proper authz)
            content_lengths = [r["content_length"] for r in baseline_responses.values()]
            if len(set(content_lengths)) == 1:
                self._add_finding(
                    "bola",
                    {
                        "type": "bola_horizontal_privilege_escalation",
                        "endpoint": endpoint,
                        "tested_ids": list(baseline_responses.keys()),
                        "description": f"Endpoint {endpoint} allows accessing all object IDs with same credentials",
                        "severity": "high",
                        "owasp": "API1:2023",
                        "recommendation": "Implement object-level authorization checks",
                        "mitre": "T1190",
                    },
                )

        self.findings["endpoints_tested"].append(endpoint)
        logger.info(f"[+] BOLA testing complete for {endpoint}")

    def test_broken_authentication(
        self, login_endpoint: str, test_credentials: list[tuple[str, str]]
    ) -> None:
        """
        Test for Broken Authentication - API2:2023.

        Tests for weak authentication mechanisms, credential stuffing vulnerabilities,
        and authentication bypass.

        Args:
            login_endpoint: Authentication endpoint
            test_credentials: List of (username, password) tuples to test
        """
        logger.info(f"[*] Testing broken authentication on {login_endpoint}")

        # Test 1: No rate limiting on authentication
        failed_attempts = 0
        for username, password in test_credentials[:20]:  # Test 20 attempts
            response = self._make_request(
                "POST", login_endpoint, json_data={"username": username, "password": password}
            )
            if response and response.status_code in [401, 403]:
                failed_attempts += 1
                time.sleep(0.1)  # Small delay

        if failed_attempts >= 10:
            self._add_finding(
                "broken_auth",
                {
                    "type": "auth_no_rate_limit",
                    "endpoint": login_endpoint,
                    "description": f"Authentication endpoint {login_endpoint} has no rate limiting (tested {failed_attempts} failed attempts)",
                    "severity": "high",
                    "owasp": "API2:2023",
                    "recommendation": "Implement rate limiting and account lockout mechanisms",
                    "mitre": "T1110",
                },
            )

        # Test 2: Weak password policy
        weak_passwords = ["password", "123456", "admin", "test", ""]
        for weak_pass in weak_passwords:
            response = self._make_request(
                "POST", login_endpoint, json_data={"username": "admin", "password": weak_pass}
            )
            if response and response.status_code == 200:
                self._add_finding(
                    "broken_auth",
                    {
                        "type": "auth_weak_password_accepted",
                        "endpoint": login_endpoint,
                        "weak_password": weak_pass,
                        "description": f"Weak password '{weak_pass}' accepted at {login_endpoint}",
                        "severity": "critical",
                        "owasp": "API2:2023",
                        "recommendation": "Enforce strong password policies",
                        "mitre": "T1110",
                    },
                )

        # Test 3: JWT token weak secrets
        response = self._make_request(
            "POST", login_endpoint, json_data={"username": "test", "password": "test"}
        )
        if response and response.status_code == 200:
            auth_header = response.headers.get("Authorization", "")
            if "Bearer" in auth_header:
                # Check for JWT
                token = auth_header.replace("Bearer ", "")
                if token.count(".") == 2:  # Valid JWT structure
                    self._add_finding(
                        "broken_auth",
                        {
                            "type": "auth_jwt_detected",
                            "endpoint": login_endpoint,
                            "description": "JWT token detected - recommend checking for weak secrets",
                            "severity": "info",
                            "owasp": "API2:2023",
                            "recommendation": "Ensure JWT uses strong secrets (HS256) or public-key cryptography (RS256)",
                            "mitre": "T1212",
                        },
                    )

        # Test 4: Authentication bypass attempts
        bypass_payloads = [
            {"username": "admin'--", "password": "anything"},
            {"username": {"$ne": None}, "password": {"$ne": None}},  # NoSQL injection
            {"username": "admin", "password": "' OR '1'='1"},
        ]

        for payload in bypass_payloads:
            response = self._make_request("POST", login_endpoint, json_data=payload)
            if response and response.status_code == 200:
                self._add_finding(
                    "broken_auth",
                    {
                        "type": "auth_bypass_possible",
                        "endpoint": login_endpoint,
                        "payload": str(payload),
                        "description": f"Possible authentication bypass with payload: {payload}",
                        "severity": "critical",
                        "owasp": "API2:2023",
                        "recommendation": "Implement proper input validation and parameterized queries",
                        "mitre": "T1190",
                    },
                )

        self.findings["endpoints_tested"].append(login_endpoint)
        logger.info(f"[+] Authentication testing complete for {login_endpoint}")

    def test_excessive_data_exposure(
        self, endpoint: str, sensitive_fields: list[str] | None = None
    ) -> None:
        """
        Test for Excessive Data Exposure - API3:2023.

        Tests if API returns more data than necessary, including sensitive fields.

        Args:
            endpoint: API endpoint to test
            sensitive_fields: List of field names that should not be returned
        """
        logger.info(f"[*] Testing excessive data exposure on {endpoint}")

        if sensitive_fields is None:
            sensitive_fields = [
                "password",
                "ssn",
                "social_security",
                "credit_card",
                "card_number",
                "cvv",
                "api_key",
                "secret",
                "token",
                "private_key",
            ]

        response = self._make_request("GET", endpoint)

        if response and response.status_code == 200:
            try:
                data = response.json()

                # Check for sensitive fields
                if isinstance(data, dict):
                    found_sensitive = []
                    for key in data.keys():
                        if any(sensitive in key.lower() for sensitive in sensitive_fields):
                            found_sensitive.append(key)

                    if found_sensitive:
                        self._add_finding(
                            "data_exposure",
                            {
                                "type": "data_excessive_exposure",
                                "endpoint": endpoint,
                                "sensitive_fields": found_sensitive,
                                "description": f"Endpoint {endpoint} returns sensitive fields: {found_sensitive}",
                                "severity": "high",
                                "owasp": "API3:2023",
                                "recommendation": "Filter response data to only include necessary fields",
                                "mitre": "T1190",
                            },
                        )

                # Check for array of objects
                if isinstance(data, list) and len(data) > 0:
                    for item in data[:5]:  # Check first 5 items
                        if isinstance(item, dict):
                            found_sensitive = []
                            for key in item.keys():
                                if any(sensitive in key.lower() for sensitive in sensitive_fields):
                                    found_sensitive.append(key)

                            if found_sensitive:
                                self._add_finding(
                                    "data_exposure",
                                    {
                                        "type": "data_excessive_exposure_array",
                                        "endpoint": endpoint,
                                        "sensitive_fields": found_sensitive,
                                        "description": f"Endpoint {endpoint} returns arrays with sensitive fields: {found_sensitive}",
                                        "severity": "high",
                                        "owasp": "API3:2023",
                                        "recommendation": "Implement response filtering for array endpoints",
                                        "mitre": "T1190",
                                    },
                                )
                                break

                # Check response size (if very large, might be returning too much data)
                content_length = len(response.content)
                if content_length > 1024 * 1024:  # > 1MB
                    self._add_finding(
                        "data_exposure",
                        {
                            "type": "data_large_response",
                            "endpoint": endpoint,
                            "response_size_bytes": content_length,
                            "description": f"Endpoint {endpoint} returns very large response ({content_length} bytes)",
                            "severity": "medium",
                            "owasp": "API3:2023",
                            "recommendation": "Implement pagination and response filtering",
                            "mitre": "T1190",
                        },
                    )

            except (json.JSONDecodeError, ValueError):
                pass

        self.findings["endpoints_tested"].append(endpoint)
        logger.info(f"[+] Data exposure testing complete for {endpoint}")

    def test_rate_limiting(self, endpoint: str, requests_count: int = 100) -> None:
        """
        Test for Unrestricted Resource Consumption - API4:2023.

        Tests if API has proper rate limiting and resource consumption controls.

        Args:
            endpoint: API endpoint to test
            requests_count: Number of requests to send
        """
        logger.info(f"[*] Testing rate limiting on {endpoint}")

        successful_requests = 0
        start_time = time.time()

        for i in range(requests_count):
            response = self._make_request("GET", endpoint)
            if response and response.status_code == 200:
                successful_requests += 1

        elapsed_time = time.time() - start_time

        # If all requests succeeded, no rate limiting
        if successful_requests == requests_count:
            requests_per_second = successful_requests / elapsed_time

            self._add_finding(
                "rate_limiting",
                {
                    "type": "rate_no_rate_limit",
                    "endpoint": endpoint,
                    "requests_sent": requests_count,
                    "requests_succeeded": successful_requests,
                    "requests_per_second": round(requests_per_second, 2),
                    "description": f"Endpoint {endpoint} has no rate limiting (accepted {requests_count} requests)",
                    "severity": "high",
                    "owasp": "API4:2023",
                    "recommendation": "Implement rate limiting (e.g., 100 requests per minute per user)",
                    "mitre": "T1498",
                },
            )

        self.findings["endpoints_tested"].append(endpoint)
        logger.info(f"[+] Rate limiting testing complete for {endpoint}")

    def test_bfla(self, admin_endpoint: str, regular_user_headers: dict[str, str]) -> None:
        """
        Test for Broken Function Level Authorization (BFLA) - API5:2023.

        Tests if regular users can access admin/privileged functionality.

        Args:
            admin_endpoint: Admin-only endpoint to test
            regular_user_headers: Headers for regular (non-admin) user
        """
        logger.info(f"[*] Testing BFLA on {admin_endpoint}")

        # Test with regular user credentials
        response = self._make_request("GET", admin_endpoint, headers=regular_user_headers)

        if response:
            if response.status_code == 200:
                self._add_finding(
                    "bfla",
                    {
                        "type": "bfla_admin_access_by_regular_user",
                        "endpoint": admin_endpoint,
                        "description": f"Regular user can access admin endpoint {admin_endpoint}",
                        "severity": "critical",
                        "owasp": "API5:2023",
                        "recommendation": "Implement function-level authorization checks for admin endpoints",
                        "mitre": "T1190",
                    },
                )

            # Try different HTTP methods
            methods = ["POST", "PUT", "DELETE", "PATCH"]
            for method in methods:
                response_method = self._make_request(
                    method, admin_endpoint, headers=regular_user_headers
                )
                if response_method and response_method.status_code in [200, 201, 204]:
                    self._add_finding(
                        "bfla",
                        {
                            "type": "bfla_privileged_method_access",
                            "endpoint": admin_endpoint,
                            "method": method,
                            "description": f"Regular user can use {method} on admin endpoint {admin_endpoint}",
                            "severity": "critical",
                            "owasp": "API5:2023",
                            "recommendation": "Restrict privileged HTTP methods to authorized users",
                            "mitre": "T1190",
                        },
                    )

        self.findings["endpoints_tested"].append(admin_endpoint)
        logger.info(f"[+] BFLA testing complete for {admin_endpoint}")

    def test_ssrf(self, endpoint: str, url_param: str = "url") -> None:
        """
        Test for Server Side Request Forgery (SSRF) - API7:2023.

        Tests if API fetches external URLs without validation, enabling SSRF.

        Args:
            endpoint: API endpoint that accepts URL parameter
            url_param: Name of the URL parameter
        """
        logger.info(f"[*] Testing SSRF on {endpoint}")

        ssrf_payloads = [
            "http://localhost:80",
            "http://127.0.0.1:22",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
            "file:///etc/passwd",
            "http://[::1]:80",
            "http://0.0.0.0:80",
        ]

        for payload in ssrf_payloads:
            response = self._make_request("GET", endpoint, params={url_param: payload})

            if response and response.status_code == 200:
                # Check if response contains internal data
                content = response.text.lower()
                if any(
                    keyword in content for keyword in ["root:", "metadata", "credentials", "secret"]
                ):
                    self._add_finding(
                        "ssrf",
                        {
                            "type": "ssrf_internal_access",
                            "endpoint": endpoint,
                            "payload": payload,
                            "description": f"SSRF vulnerability at {endpoint} - accessed internal resource: {payload}",
                            "severity": "critical",
                            "owasp": "API7:2023",
                            "recommendation": "Validate and sanitize user-supplied URLs, use allowlist",
                            "mitre": "T1190",
                        },
                    )
                else:
                    # Still potentially vulnerable if it accepts internal URLs
                    self._add_finding(
                        "ssrf",
                        {
                            "type": "ssrf_potential",
                            "endpoint": endpoint,
                            "payload": payload,
                            "description": f"Endpoint {endpoint} accepts internal URLs (potential SSRF): {payload}",
                            "severity": "high",
                            "owasp": "API7:2023",
                            "recommendation": "Implement URL validation and restrict to external resources",
                            "mitre": "T1190",
                        },
                    )

        self.findings["endpoints_tested"].append(endpoint)
        logger.info(f"[+] SSRF testing complete for {endpoint}")

    def test_security_misconfiguration(self, endpoints: list[str]) -> None:
        """
        Test for Security Misconfiguration - API8:2023.

        Tests for common security misconfigurations like verbose errors,
        missing security headers, and debug mode.

        Args:
            endpoints: List of endpoints to test
        """
        logger.info("[*] Testing security misconfigurations")

        for endpoint in endpoints:
            response = self._make_request("GET", endpoint)

            if response:
                # Check for missing security headers
                security_headers = [
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                ]

                missing_headers = [h for h in security_headers if h not in response.headers]
                if missing_headers:
                    self._add_finding(
                        "misconfig",
                        {
                            "type": "misconfig_missing_security_headers",
                            "endpoint": endpoint,
                            "missing_headers": missing_headers,
                            "description": f"Endpoint {endpoint} missing security headers: {missing_headers}",
                            "severity": "medium",
                            "owasp": "API8:2023",
                            "recommendation": "Implement all recommended security headers",
                            "mitre": "T1190",
                        },
                    )

                # Check for verbose error messages
                if response.status_code >= 500:
                    if any(
                        keyword in response.text.lower()
                        for keyword in ["stack trace", "exception", "debug", "sql", "database"]
                    ):
                        self._add_finding(
                            "misconfig",
                            {
                                "type": "misconfig_verbose_errors",
                                "endpoint": endpoint,
                                "status_code": response.status_code,
                                "description": f"Endpoint {endpoint} returns verbose error messages",
                                "severity": "medium",
                                "owasp": "API8:2023",
                                "recommendation": "Disable debug mode and implement generic error messages",
                                "mitre": "T1190",
                            },
                        )

                # Check for CORS misconfiguration
                cors_header = response.headers.get("Access-Control-Allow-Origin", "")
                if cors_header == "*":
                    self._add_finding(
                        "misconfig",
                        {
                            "type": "misconfig_cors_wildcard",
                            "endpoint": endpoint,
                            "description": f"Endpoint {endpoint} allows CORS from all origins (*)",
                            "severity": "medium",
                            "owasp": "API8:2023",
                            "recommendation": "Restrict CORS to specific trusted origins",
                            "mitre": "T1190",
                        },
                    )

        logger.info("[+] Security misconfiguration testing complete")

    def scan_all(
        self,
        endpoints: dict[str, Any] | None = None,
        test_credentials: list[tuple[str, str]] | None = None,
    ) -> dict[str, Any]:
        """
        Run all OWASP API Security Top 10 tests.

        Args:
            endpoints: Dict of endpoint configurations for testing
            test_credentials: List of (username, password) tuples

        Returns:
            Dict containing all findings
        """
        logger.info("[!] Starting comprehensive OWASP API Security Top 10 scan...")

        if endpoints:
            # BOLA tests
            if "bola_endpoints" in endpoints:
                for ep in endpoints["bola_endpoints"]:
                    self.test_bola(ep["path"], ep.get("id_param", "id"))

            # Authentication tests
            if "auth_endpoint" in endpoints:
                if test_credentials:
                    self.test_broken_authentication(endpoints["auth_endpoint"], test_credentials)

            # Data exposure tests
            if "data_endpoints" in endpoints:
                for ep in endpoints["data_endpoints"]:
                    self.test_excessive_data_exposure(ep)

            # Rate limiting tests
            if "rate_limit_endpoints" in endpoints:
                for ep in endpoints["rate_limit_endpoints"]:
                    self.test_rate_limiting(ep)

            # BFLA tests
            if "admin_endpoints" in endpoints and "regular_user_headers" in endpoints:
                for ep in endpoints["admin_endpoints"]:
                    self.test_bfla(ep, endpoints["regular_user_headers"])

            # SSRF tests
            if "ssrf_endpoints" in endpoints:
                for ep in endpoints["ssrf_endpoints"]:
                    self.test_ssrf(ep["path"], ep.get("url_param", "url"))

            # Misconfiguration tests
            all_endpoints = []
            for key in ["bola_endpoints", "data_endpoints", "rate_limit_endpoints"]:
                if key in endpoints:
                    if key == "bola_endpoints":
                        all_endpoints.extend([e["path"] for e in endpoints[key]])
                    else:
                        all_endpoints.extend(endpoints[key])

            if all_endpoints:
                self.test_security_misconfiguration(all_endpoints)

        logger.info("[+] API security scan complete!")
        logger.info(
            f"[+] Findings: Critical={self.findings['summary']['critical']}, "
            f"High={self.findings['summary']['high']}, "
            f"Medium={self.findings['summary']['medium']}, "
            f"Low={self.findings['summary']['low']}"
        )

        return self.findings

    def save_results(self, output_file: Path) -> None:
        """Save scan results to JSON file."""
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            json.dump(self.findings, f, indent=2)

        logger.info(f"[+] Results saved to {output_file}")


def main():
    """CLI entry point for API fuzzer."""
    import argparse

    parser = argparse.ArgumentParser(
        description="OWASP API Security Top 10 Fuzzer - Comprehensive API security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test specific endpoint for BOLA
  python api_fuzzer.py --url https://api.example.com --test bola --endpoint /api/users/{id}

  # Test authentication
  python api_fuzzer.py --url https://api.example.com --test auth --endpoint /api/login

  # Full OWASP API Top 10 scan
  python api_fuzzer.py --url https://api.example.com --scan-all --output api_findings.json

OWASP API Security Top 10 2023:
  API1:2023 - Broken Object Level Authorization (BOLA)
  API2:2023 - Broken Authentication
  API3:2023 - Broken Object Property Level Authorization
  API4:2023 - Unrestricted Resource Consumption
  API5:2023 - Broken Function Level Authorization
  API7:2023 - Server Side Request Forgery
  API8:2023 - Security Misconfiguration
        """,
    )

    parser.add_argument("--url", required=True, help="Base URL of the API")
    parser.add_argument(
        "--test",
        choices=["bola", "auth", "data", "rate", "bfla", "ssrf", "misconfig"],
        help="Specific test to run",
    )
    parser.add_argument("--endpoint", help="Endpoint to test")
    parser.add_argument("--scan-all", action="store_true", help="Run all tests")
    parser.add_argument("--headers", help="JSON file with custom headers")
    parser.add_argument(
        "--output", type=Path, default=Path("output/api_scan.json"), help="Output file path"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(message)s")

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║        OWASP API Security Top 10 Fuzzer v1.0              ║
    ║           Authorized Security Testing Only                ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    # Load custom headers
    headers = {}
    if args.headers:
        with open(args.headers) as f:
            headers = json.load(f)

    try:
        fuzzer = APIFuzzer(base_url=args.url, headers=headers)

        if args.test:
            if args.test == "bola" and args.endpoint:
                fuzzer.test_bola(args.endpoint)
            elif args.test == "auth" and args.endpoint:
                test_creds = [("admin", "admin"), ("user", "pass"), ("test", "test")]
                fuzzer.test_broken_authentication(args.endpoint, test_creds)
            elif args.test == "data" and args.endpoint:
                fuzzer.test_excessive_data_exposure(args.endpoint)
            elif args.test == "rate" and args.endpoint:
                fuzzer.test_rate_limiting(args.endpoint)
            elif args.test == "ssrf" and args.endpoint:
                fuzzer.test_ssrf(args.endpoint)
            elif args.test == "misconfig":
                endpoints = [args.endpoint] if args.endpoint else ["/"]
                fuzzer.test_security_misconfiguration(endpoints)
            else:
                print("[-] Please provide --endpoint for the selected test")
                return 1
        elif args.scan_all:
            # Basic scan with common endpoints
            endpoints_config = {
                "data_endpoints": ["/", "/api", "/api/v1"],
                "rate_limit_endpoints": ["/api/login"],
            }
            fuzzer.scan_all(endpoints=endpoints_config)
        else:
            print("[-] Please specify --test or --scan-all")
            return 1

        fuzzer.save_results(args.output)

        return 0

    except Exception as e:
        logger.error(f"[-] Error: {e}")
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
