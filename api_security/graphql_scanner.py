"""
GraphQL Security Scanner

Specialized security testing tool for GraphQL APIs.
Tests for introspection exposure, query depth attacks, batch query abuse,
and other GraphQL-specific vulnerabilities.

GraphQL Security Risks:
- Introspection enabled in production
- Unlimited query depth (DoS)
- Batch query abuse
- Field suggestion enumeration
- Circular queries
- Alias-based DDoS

MITRE ATT&CK Mapping:
- T1190: Exploit Public-Facing Application
- T1499: Endpoint Denial of Service

Author: David Dashti
License: Educational/Research Use Only
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

# Configure logging
logger = logging.getLogger(__name__)


class GraphQLScanner:
    """
    GraphQL security scanner for identifying GraphQL-specific vulnerabilities.

    Features:
    - Introspection query testing
    - Query depth attack detection
    - Batch query abuse testing
    - Field suggestion enumeration
    - Circular query detection
    - DoS via aliases
    """

    def __init__(self, graphql_url: str, headers: dict[str, str] | None = None):
        """
        Initialize GraphQL scanner.

        Args:
            graphql_url: GraphQL endpoint URL
            headers: Custom headers for requests
        """
        self.graphql_url = graphql_url
        self.headers = headers or {"Content-Type": "application/json"}
        self.session = requests.Session()
        self.session.headers.update(self.headers)

        self.findings = {
            "scan_metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "scanner": "GraphQLScanner",
                "target_url": self.graphql_url,
            },
            "introspection": [],
            "dos": [],
            "enumeration": [],
            "misconfig": [],
            "schema": None,
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

        logger.info(f"[+] GraphQL scanner initialized for {self.graphql_url}")

    def _add_finding(self, category: str, finding: dict[str, Any]) -> None:
        """Add finding and update severity counts."""
        self.findings[category].append(finding)
        severity = finding.get("severity", "info")
        self.findings["summary"][severity] = self.findings["summary"].get(severity, 0) + 1

    def _graphql_query(
        self, query: str, variables: dict[str, Any] | None = None
    ) -> requests.Response | None:
        """Execute GraphQL query."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            response = self.session.post(self.graphql_url, json=payload, timeout=30)
            return response
        except requests.exceptions.RequestException as e:
            logger.debug(f"GraphQL query error: {e}")
            return None

    def test_introspection(self) -> None:
        """
        Test if GraphQL introspection is enabled.

        Introspection should be disabled in production to prevent schema disclosure.
        """
        logger.info("[*] Testing GraphQL introspection...")

        introspection_query = """
        {
          __schema {
            types {
              name
              kind
              description
              fields {
                name
                description
                type {
                  name
                  kind
                }
              }
            }
          }
        }
        """

        response = self._graphql_query(introspection_query)

        if response and response.status_code == 200:
            try:
                data = response.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    schema = data["data"]["__schema"]
                    types = schema.get("types", [])

                    self.findings["schema"] = schema

                    self._add_finding(
                        "introspection",
                        {
                            "type": "introspection_enabled",
                            "description": "GraphQL introspection is enabled in production",
                            "severity": "high",
                            "types_count": len(types),
                            "recommendation": "Disable introspection in production environments",
                            "mitre": "T1190",
                        },
                    )

                    # Check for sensitive type names
                    sensitive_keywords = [
                        "admin",
                        "internal",
                        "private",
                        "secret",
                        "key",
                        "password",
                    ]
                    sensitive_types = []

                    for type_obj in types:
                        type_name = type_obj.get("name", "").lower()
                        if any(keyword in type_name for keyword in sensitive_keywords):
                            sensitive_types.append(type_obj.get("name"))

                    if sensitive_types:
                        self._add_finding(
                            "introspection",
                            {
                                "type": "introspection_sensitive_types",
                                "sensitive_types": sensitive_types,
                                "description": f"GraphQL schema contains sensitive type names: {sensitive_types}",
                                "severity": "medium",
                                "recommendation": "Review and rename sensitive types or disable introspection",
                                "mitre": "T1190",
                            },
                        )

                    logger.info(f"[+] Introspection enabled: {len(types)} types discovered")
                else:
                    logger.info("[+] Introspection disabled or restricted")

            except (json.JSONDecodeError, KeyError) as e:
                logger.debug(f"Error parsing introspection response: {e}")

    def test_query_depth(self, max_depth: int = 20) -> None:
        """
        Test for query depth DoS vulnerability.

        Args:
            max_depth: Maximum query depth to test
        """
        logger.info(f"[*] Testing query depth attacks (max depth: {max_depth})...")

        # Build a deeply nested query
        query_parts = []
        closing_braces = []

        for i in range(max_depth):
            query_parts.append(f"nested{i} {{")
            closing_braces.append("}")

        deep_query = "{ " + " ".join(query_parts) + "id" + "".join(reversed(closing_braces)) + " }"

        response = self._graphql_query(deep_query)

        if response and response.status_code == 200:
            try:
                data = response.json()
                if "data" in data or not data.get("errors"):
                    self._add_finding(
                        "dos",
                        {
                            "type": "dos_unlimited_depth",
                            "description": f"GraphQL accepts queries with depth {max_depth} (DoS risk)",
                            "severity": "high",
                            "tested_depth": max_depth,
                            "recommendation": "Implement query depth limiting (recommended max: 7-10)",
                            "mitre": "T1499",
                        },
                    )
                    logger.info(f"[!] Deep query accepted: {max_depth} levels")
                else:
                    logger.info(f"[+] Query depth limited (depth {max_depth} rejected)")
            except (json.JSONDecodeError, KeyError):
                pass

    def test_batch_query_abuse(self, batch_size: int = 100) -> None:
        """
        Test for batch query abuse (query batching DoS).

        Args:
            batch_size: Number of queries to batch
        """
        logger.info(f"[*] Testing batch query abuse (batch size: {batch_size})...")

        # Create array of queries
        batch_payload = []
        for i in range(batch_size):
            batch_payload.append({"query": "{ __typename }"})

        try:
            response = self.session.post(self.graphql_url, json=batch_payload, timeout=30)

            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) == batch_size:
                        self._add_finding(
                            "dos",
                            {
                                "type": "dos_batch_query_abuse",
                                "description": f"GraphQL accepts batch queries ({batch_size} queries per request)",
                                "severity": "high",
                                "batch_size": batch_size,
                                "recommendation": "Implement batch query limiting (recommended max: 5-10 queries)",
                                "mitre": "T1499",
                            },
                        )
                        logger.info(f"[!] Batch query accepted: {batch_size} queries")
                    else:
                        logger.info("[+] Batch queries limited or disabled")
                except (json.JSONDecodeError, ValueError):
                    pass

        except requests.exceptions.RequestException as e:
            logger.debug(f"Batch query test error: {e}")

    def test_alias_dos(self, alias_count: int = 100) -> None:
        """
        Test for alias-based DoS attack.

        Args:
            alias_count: Number of aliases to test
        """
        logger.info(f"[*] Testing alias-based DoS (aliases: {alias_count})...")

        # Build query with many aliases
        aliases = [f"alias{i}: __typename" for i in range(alias_count)]
        alias_query = "{ " + " ".join(aliases) + " }"

        response = self._graphql_query(alias_query)

        if response and response.status_code == 200:
            try:
                data = response.json()
                if "data" in data:
                    result_count = len(data["data"])
                    if result_count >= alias_count:
                        self._add_finding(
                            "dos",
                            {
                                "type": "dos_alias_abuse",
                                "description": f"GraphQL accepts queries with {alias_count} aliases (DoS risk)",
                                "severity": "medium",
                                "alias_count": alias_count,
                                "recommendation": "Implement alias count limiting",
                                "mitre": "T1499",
                            },
                        )
                        logger.info(f"[!] Alias DoS possible: {alias_count} aliases accepted")
                    else:
                        logger.info("[+] Alias count limited")
            except (json.JSONDecodeError, KeyError):
                pass

    def test_field_suggestions(self) -> None:
        """Test if GraphQL provides field suggestions for typos."""
        logger.info("[*] Testing field suggestion enumeration...")

        # Try invalid field name
        invalid_query = "{ invalidFieldName12345 }"

        response = self._graphql_query(invalid_query)

        if response and response.status_code == 200:
            try:
                data = response.json()
                if "errors" in data:
                    error_msg = str(data["errors"])
                    if "did you mean" in error_msg.lower() or "suggestion" in error_msg.lower():
                        self._add_finding(
                            "enumeration",
                            {
                                "type": "enum_field_suggestions",
                                "description": "GraphQL provides field name suggestions (enables enumeration)",
                                "severity": "low",
                                "error_message": error_msg[:200],
                                "recommendation": "Disable field suggestions in production",
                                "mitre": "T1190",
                            },
                        )
                        logger.info("[!] Field suggestions enabled")
                    else:
                        logger.info("[+] Field suggestions disabled")
            except (json.JSONDecodeError, KeyError):
                pass

    def test_error_verbosity(self) -> None:
        """Test for verbose error messages."""
        logger.info("[*] Testing error message verbosity...")

        # Send malformed query
        malformed_query = "{ { { invalid"

        response = self._graphql_query(malformed_query)

        if response:
            try:
                data = response.json()
                if "errors" in data:
                    error_msg = str(data["errors"])

                    # Check for stack traces or internal paths
                    if any(
                        keyword in error_msg.lower()
                        for keyword in ["stack", "traceback", "file:", "line:"]
                    ):
                        self._add_finding(
                            "misconfig",
                            {
                                "type": "misconfig_verbose_errors",
                                "description": "GraphQL returns verbose error messages with stack traces",
                                "severity": "medium",
                                "recommendation": "Configure production error handling to return generic errors",
                                "mitre": "T1190",
                            },
                        )
                        logger.info("[!] Verbose error messages detected")
                    else:
                        logger.info("[+] Error messages properly sanitized")
            except (json.JSONDecodeError, ValueError):
                pass

    def scan_all(self) -> dict[str, Any]:
        """
        Run all GraphQL security tests.

        Returns:
            Dict containing all findings
        """
        logger.info("[!] Starting comprehensive GraphQL security scan...")

        self.test_introspection()
        self.test_query_depth(max_depth=20)
        self.test_batch_query_abuse(batch_size=100)
        self.test_alias_dos(alias_count=100)
        self.test_field_suggestions()
        self.test_error_verbosity()

        logger.info("[+] GraphQL security scan complete!")
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
    """CLI entry point for GraphQL scanner."""
    import argparse

    parser = argparse.ArgumentParser(
        description="GraphQL Security Scanner - Identify GraphQL-specific vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full GraphQL security scan
  python graphql_scanner.py --url https://api.example.com/graphql --scan-all

  # Test specific issues
  python graphql_scanner.py --url https://api.example.com/graphql --test introspection
  python graphql_scanner.py --url https://api.example.com/graphql --test depth
  python graphql_scanner.py --url https://api.example.com/graphql --test batch

GraphQL Security Risks:
  - Introspection enabled in production
  - Unlimited query depth (DoS)
  - Batch query abuse (DoS)
  - Alias-based DDoS
  - Field suggestion enumeration
  - Verbose error messages
        """,
    )

    parser.add_argument("--url", required=True, help="GraphQL endpoint URL")
    parser.add_argument(
        "--test",
        choices=["introspection", "depth", "batch", "alias", "suggestions", "errors"],
        help="Specific test to run",
    )
    parser.add_argument("--scan-all", action="store_true", help="Run all GraphQL tests")
    parser.add_argument("--headers", help="JSON file with custom headers")
    parser.add_argument(
        "--output", type=Path, default=Path("output/graphql_scan.json"), help="Output file path"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(message)s")

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║          GraphQL Security Scanner v1.0                    ║
    ║           Authorized Security Testing Only                ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    # Load custom headers
    headers = {}
    if args.headers:
        with open(args.headers) as f:
            headers = json.load(f)

    try:
        scanner = GraphQLScanner(graphql_url=args.url, headers=headers)

        if args.test:
            if args.test == "introspection":
                scanner.test_introspection()
            elif args.test == "depth":
                scanner.test_query_depth()
            elif args.test == "batch":
                scanner.test_batch_query_abuse()
            elif args.test == "alias":
                scanner.test_alias_dos()
            elif args.test == "suggestions":
                scanner.test_field_suggestions()
            elif args.test == "errors":
                scanner.test_error_verbosity()
        elif args.scan_all:
            scanner.scan_all()
        else:
            print("[-] Please specify --test or --scan-all")
            return 1

        scanner.save_results(args.output)

        return 0

    except Exception as e:
        logger.error(f"[-] Error: {e}")
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
