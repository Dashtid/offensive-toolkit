#!/usr/bin/env python3
"""
DNS Resolver - Multi-Resolver DNS Lookups

Performs DNS queries using multiple resolvers for reliability and comparison.

[!] AUTHORIZATION REQUIRED: Only use on authorized domains.

Usage:
    python dns_resolver.py --domain <domain> [options]

Examples:
    # Basic DNS lookup
    python dns_resolver.py --domain example.com

    # Use specific resolvers
    python dns_resolver.py --domain example.com --resolvers 8.8.8.8,1.1.1.1

    # Query specific record types
    python dns_resolver.py --domain example.com --types A,AAAA,MX,TXT

Author: David Dashti
Date: 2025-10-15
MITRE ATT&CK: T1590.002 (Gather Victim Network Information: DNS)
"""

import argparse
import sys
from ipaddress import ip_address
from typing import Any

import dns.exception
import dns.resolver

from offensive_toolkit.utils.config import load_config
from offensive_toolkit.utils.helpers import check_authorization, sanitize_filename, validate_domain
from offensive_toolkit.utils.logger import get_logger

logger = get_logger(__name__)


# Common public DNS resolvers
DEFAULT_RESOLVERS = [
    "8.8.8.8",  # Google
    "8.8.4.4",  # Google Secondary
    "1.1.1.1",  # Cloudflare
    "1.0.0.1",  # Cloudflare Secondary
    "9.9.9.9",  # Quad9
    "208.67.222.222",  # OpenDNS
]

# DNS record types
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR"]


class DNSResolver:
    """
    Multi-resolver DNS lookup tool.

    Performs DNS queries using multiple resolvers for reliability.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize DNS resolver.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or load_config()
        self.resolvers = DEFAULT_RESOLVERS
        logger.info(f"Initialized {self.__class__.__name__}")

    def query_record(
        self, domain: str, record_type: str = "A", resolver_ip: str | None = None
    ) -> list[str]:
        """
        Query DNS record from specified resolver.

        Args:
            domain: Domain to query
            record_type: DNS record type (A, AAAA, MX, etc.)
            resolver_ip: Optional specific resolver IP

        Returns:
            List of DNS record values
        """
        results = []

        try:
            resolver = dns.resolver.Resolver()

            if resolver_ip:
                resolver.nameservers = [resolver_ip]

            timeout = self.config.get("timeouts", {}).get("connection", 5)
            resolver.timeout = timeout
            resolver.lifetime = timeout

            answers = resolver.resolve(domain, record_type)

            for rdata in answers:
                if record_type == "MX":
                    results.append(f"{rdata.preference} {rdata.exchange}")
                elif record_type == "TXT":
                    results.append(str(rdata).strip('"'))
                elif record_type == "SOA":
                    results.append(f"{rdata.mname} {rdata.rname}")
                else:
                    results.append(str(rdata))

            logger.debug(f"Found {len(results)} {record_type} records for {domain}")

        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            logger.debug(f"No {record_type} records found for {domain}")
        except dns.exception.Timeout:
            logger.warning(f"DNS query timeout for {domain}")
        except Exception as e:
            logger.error(f"DNS query error for {domain}: {e}")

        return results

    def resolve_multiple_resolvers(
        self, domain: str, record_type: str = "A"
    ) -> dict[str, list[str]]:
        """
        Query DNS record using multiple resolvers for comparison.

        Args:
            domain: Domain to query
            record_type: DNS record type

        Returns:
            Dictionary mapping resolver IP to results
        """
        results = {}

        for resolver_ip in self.resolvers:
            records = self.query_record(domain, record_type, resolver_ip)
            if records:
                results[resolver_ip] = records
                logger.debug(f"Resolver {resolver_ip}: {len(records)} records")

        return results

    def comprehensive_lookup(
        self, domain: str, record_types: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Perform comprehensive DNS lookup for all record types.

        Args:
            domain: Domain to query
            record_types: Optional list of record types to query

        Returns:
            Dictionary with all DNS records
        """
        if record_types is None:
            record_types = RECORD_TYPES

        results = {}

        for record_type in record_types:
            logger.info(f"Querying {record_type} records for {domain}")
            records = self.query_record(domain, record_type)

            if records:
                results[record_type] = records
                print(f"[+] {record_type}: {len(records)} records found")

        return results

    def reverse_lookup(self, ip: str) -> str | None:
        """
        Perform reverse DNS lookup for IP address.

        Args:
            ip: IP address to lookup

        Returns:
            Hostname or None if not found
        """
        try:
            # Validate IP
            ip_address(ip)

            # Reverse lookup
            import socket

            hostname = socket.gethostbyaddr(ip)[0]
            logger.info(f"Reverse DNS: {ip} -> {hostname}")
            return hostname

        except Exception as e:
            logger.debug(f"Reverse lookup failed for {ip}: {e}")
            return None

    def run(
        self, domain: str, record_types: list[str] | None = None, compare_resolvers: bool = False
    ) -> dict[str, Any]:
        """
        Execute DNS resolution.

        Args:
            domain: Domain to resolve
            record_types: Optional list of record types
            compare_resolvers: Compare results across multiple resolvers

        Returns:
            DNS lookup results
        """
        # Authorization check
        if not check_authorization(domain, self.config):
            logger.error(f"Domain {domain} not authorized")
            return {"error": "Not authorized"}

        # Validate domain
        if not validate_domain(domain):
            logger.error(f"Invalid domain: {domain}")
            return {"error": "Invalid domain"}

        logger.info(f"Starting DNS resolution for {domain}")

        results = {"domain": domain, "records": {}}

        if compare_resolvers:
            # Compare results across resolvers
            for record_type in record_types or ["A", "AAAA"]:
                resolver_results = self.resolve_multiple_resolvers(domain, record_type)
                if resolver_results:
                    results["records"][record_type] = resolver_results
        else:
            # Standard comprehensive lookup
            dns_records = self.comprehensive_lookup(domain, record_types)
            results["records"] = dns_records

        logger.info(f"DNS resolution complete: {len(results['records'])} record types found")
        self._save_results(results)

        return results

    def _save_results(self, results: dict[str, Any]) -> None:
        """
        Save DNS results to output directory.

        Args:
            results: Results dictionary to save
        """
        import json
        from datetime import datetime
        from pathlib import Path

        output_dir = Path(self.config.get("output", {}).get("directory", "output"))
        output_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_safe = sanitize_filename(results["domain"])
        filename = f"dns_{domain_safe}_{timestamp}.json"
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
        description="DNS Resolver - Multi-Resolver DNS Lookups\n"
        "[!] For authorized reconnaissance only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--domain", required=True, help="Domain to resolve")

    parser.add_argument(
        "--types",
        default="A,AAAA,MX,NS,TXT",
        help="Comma-separated DNS record types (default: A,AAAA,MX,NS,TXT)",
    )

    parser.add_argument("--resolvers", help="Comma-separated list of custom DNS resolvers")

    parser.add_argument(
        "--compare", action="store_true", help="Compare results across multiple resolvers"
    )

    parser.add_argument("--reverse", help="Perform reverse DNS lookup for IP address")

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
    print("[!] DNS Resolver - For Authorized Reconnaissance Only")
    print("=" * 70 + "\n")

    # Create resolver
    resolver = DNSResolver(config)

    # Custom resolvers
    if args.resolvers:
        resolver.resolvers = args.resolvers.split(",")

    # Reverse lookup
    if args.reverse:
        hostname = resolver.reverse_lookup(args.reverse)
        if hostname:
            print(f"[+] Reverse DNS: {args.reverse} -> {hostname}")
            return 0
        print(f"[-] No reverse DNS found for {args.reverse}")
        return 1

    # Parse record types
    record_types = args.types.split(",") if args.types else None

    # Run DNS resolution
    results = resolver.run(args.domain, record_types, args.compare)

    if "error" in results:
        print(f"\n[-] Error: {results['error']}")
        return 1

    # Print summary
    print(f"\n[+] DNS Resolution Summary for {results['domain']}:")
    print(f"    Record Types Found: {len(results['records'])}")

    for record_type, records in results["records"].items():
        if isinstance(records, dict):
            # Resolver comparison
            print(f"\n[+] {record_type} Records (by resolver):")
            for resolver_ip, values in records.items():
                print(f"    {resolver_ip}: {', '.join(values)}")
        else:
            # Standard results
            print(f"\n[+] {record_type} Records:")
            for record in records:
                print(f"    - {record}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
