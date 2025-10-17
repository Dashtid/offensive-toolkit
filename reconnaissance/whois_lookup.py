#!/usr/bin/env python3
"""
WHOIS Lookup - Domain Intelligence Gathering

Performs WHOIS lookups and extracts domain registration information.

[!] AUTHORIZATION REQUIRED: Only use on authorized domains.

Usage:
    python whois_lookup.py --domain <domain> [options]

Examples:
    # Basic WHOIS lookup
    python whois_lookup.py --domain example.com

    # Lookup with parsed output
    python whois_lookup.py --domain example.com --parse

    # Lookup multiple domains
    python whois_lookup.py --file domains.txt

Author: David Dashti
Date: 2025-10-15
MITRE ATT&CK: T1590.001 (Gather Victim Network Information: Domain Properties)
"""

import argparse
import re
import socket
import sys
from datetime import datetime
from typing import Any

from utils.config import load_config
from utils.helpers import check_authorization, sanitize_filename, validate_domain
from utils.logger import get_logger

logger = get_logger(__name__)


# WHOIS servers by TLD
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "edu": "whois.educause.edu",
    "gov": "whois.nic.gov",
    "mil": "whois.nic.mil",
    "int": "whois.iana.org",
    "io": "whois.nic.io",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "jp": "whois.jprs.jp",
    "cn": "whois.cnnic.cn",
    "ru": "whois.tcinet.ru",
    "br": "whois.registro.br",
    "in": "whois.registry.in",
    "mx": "whois.mx",
    "es": "whois.nic.es",
    "it": "whois.nic.it",
    "nl": "whois.domain-registry.nl",
    "se": "whois.iis.se",
    "no": "whois.norid.no",
    "pl": "whois.dns.pl",
    "ch": "whois.nic.ch",
}


class WHOISLookup:
    """
    WHOIS lookup and domain intelligence gathering tool.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize WHOIS lookup tool.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or load_config()
        logger.info(f"Initialized {self.__class__.__name__}")

    def query_whois_server(self, domain: str, whois_server: str | None = None) -> str:
        """
        Query WHOIS server for domain information.

        Args:
            domain: Domain to query
            whois_server: Optional specific WHOIS server

        Returns:
            Raw WHOIS response
        """
        # Determine WHOIS server
        if whois_server is None:
            tld = domain.split(".")[-1].lower()
            whois_server = WHOIS_SERVERS.get(tld, "whois.iana.org")

        logger.info(f"Querying WHOIS server {whois_server} for {domain}")

        try:
            # Connect to WHOIS server
            timeout = self.config.get("timeouts", {}).get("connection", 10)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((whois_server, 43))

            # Send query
            query = f"{domain}\r\n"
            sock.send(query.encode("utf-8"))

            # Receive response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data

            sock.close()

            response_text = response.decode("utf-8", errors="ignore")
            logger.debug(f"Received {len(response_text)} bytes from WHOIS server")

            # Check for referral to another server
            referral_match = re.search(
                r"(?:Registrar WHOIS Server|ReferralServer|Whois Server):\s*(?:whois://)?(.+)",
                response_text,
                re.IGNORECASE,
            )

            if referral_match:
                referral_server = referral_match.group(1).strip()
                logger.info(f"Following referral to {referral_server}")
                return self.query_whois_server(domain, referral_server)

            return response_text

        except TimeoutError:
            logger.error(f"WHOIS query timeout for {domain}")
            return ""
        except Exception as e:
            logger.error(f"WHOIS query error for {domain}: {e}")
            return ""

    def parse_whois(self, whois_text: str) -> dict[str, Any]:
        """
        Parse WHOIS response text into structured data.

        Args:
            whois_text: Raw WHOIS response

        Returns:
            Parsed WHOIS data
        """
        parsed = {
            "domain_name": None,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "status": [],
            "registrant": None,
            "admin_contact": None,
            "tech_contact": None,
            "dnssec": None,
        }

        lines = whois_text.split("\n")

        for line in lines:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("%") or line.startswith("#"):
                continue

            # Domain name
            if re.match(r"Domain Name:\s*(.+)", line, re.IGNORECASE):
                parsed["domain_name"] = (
                    re.search(r"Domain Name:\s*(.+)", line, re.IGNORECASE).group(1).strip()
                )

            # Registrar
            elif re.match(r"Registrar:\s*(.+)", line, re.IGNORECASE):
                parsed["registrar"] = (
                    re.search(r"Registrar:\s*(.+)", line, re.IGNORECASE).group(1).strip()
                )

            # Creation date
            elif re.match(r"(?:Creation Date|Created):\s*(.+)", line, re.IGNORECASE):
                parsed["creation_date"] = (
                    re.search(r"(?:Creation Date|Created):\s*(.+)", line, re.IGNORECASE)
                    .group(1)
                    .strip()
                )

            # Expiration date
            elif re.match(r"(?:Expir|Registry Expiry Date):\s*(.+)", line, re.IGNORECASE):
                parsed["expiration_date"] = (
                    re.search(r"(?:Expir|Registry Expiry Date):\s*(.+)", line, re.IGNORECASE)
                    .group(1)
                    .strip()
                )

            # Updated date
            elif re.match(r"(?:Updated Date|Last Updated):\s*(.+)", line, re.IGNORECASE):
                parsed["updated_date"] = (
                    re.search(r"(?:Updated Date|Last Updated):\s*(.+)", line, re.IGNORECASE)
                    .group(1)
                    .strip()
                )

            # Name servers
            elif re.match(r"Name Server:\s*(.+)", line, re.IGNORECASE):
                ns = re.search(r"Name Server:\s*(.+)", line, re.IGNORECASE).group(1).strip()
                if ns not in parsed["name_servers"]:
                    parsed["name_servers"].append(ns)

            # Status
            elif re.match(r"(?:Domain )?Status:\s*(.+)", line, re.IGNORECASE):
                status = (
                    re.search(r"(?:Domain )?Status:\s*(.+)", line, re.IGNORECASE).group(1).strip()
                )
                if status not in parsed["status"]:
                    parsed["status"].append(status)

            # DNSSEC
            elif re.match(r"DNSSEC:\s*(.+)", line, re.IGNORECASE):
                parsed["dnssec"] = (
                    re.search(r"DNSSEC:\s*(.+)", line, re.IGNORECASE).group(1).strip()
                )

        return parsed

    def bulk_lookup(self, domains: list[str]) -> dict[str, Any]:
        """
        Perform WHOIS lookup on multiple domains.

        Args:
            domains: List of domains to query

        Returns:
            Results for all domains
        """
        results = {}

        for domain in domains:
            logger.info(f"Looking up {domain}")
            print(f"[*] Looking up {domain}...")

            whois_text = self.query_whois_server(domain)
            if whois_text:
                parsed = self.parse_whois(whois_text)
                results[domain] = {"raw": whois_text, "parsed": parsed}
            else:
                results[domain] = {"error": "WHOIS query failed"}

        return results

    def run(self, domain: str, parse: bool = True) -> dict[str, Any]:
        """
        Execute WHOIS lookup.

        Args:
            domain: Domain to lookup
            parse: Parse WHOIS response

        Returns:
            WHOIS lookup results
        """
        # Authorization check
        if not check_authorization(domain, self.config):
            logger.error(f"Domain {domain} not authorized")
            return {"error": "Not authorized"}

        # Validate domain
        if not validate_domain(domain):
            logger.error(f"Invalid domain: {domain}")
            return {"error": "Invalid domain"}

        logger.info(f"Starting WHOIS lookup for {domain}")
        print(f"\n[*] Performing WHOIS lookup for {domain}")

        # Query WHOIS
        whois_text = self.query_whois_server(domain)

        if not whois_text:
            return {"error": "WHOIS query failed"}

        results = {"domain": domain, "raw": whois_text, "timestamp": datetime.now().isoformat()}

        # Parse if requested
        if parse:
            print("[*] Parsing WHOIS data...")
            parsed = self.parse_whois(whois_text)
            results["parsed"] = parsed

        logger.info(f"WHOIS lookup complete for {domain}")
        self._save_results(results)

        return results

    def _save_results(self, results: dict[str, Any]) -> None:
        """
        Save WHOIS results to output directory.

        Args:
            results: Results dictionary to save
        """
        import json
        from pathlib import Path

        output_dir = Path(self.config.get("output", {}).get("directory", "output"))
        output_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_safe = sanitize_filename(results["domain"])
        filename = f"whois_{domain_safe}_{timestamp}.json"
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
        description="WHOIS Lookup - Domain Intelligence Gathering\n"
        "[!] For authorized reconnaissance only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--domain", help="Domain to lookup")

    parser.add_argument("--file", help="File containing list of domains (one per line)")

    parser.add_argument("--no-parse", action="store_true", help="Don't parse WHOIS response")

    parser.add_argument("--server", help="Specific WHOIS server to query")

    parser.add_argument("--config", help="Path to configuration file")

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    if not args.domain and not args.file:
        parser.error("Either --domain or --file is required")

    # Load configuration
    config = load_config(args.config) if args.config else load_config()

    # Set log level
    if args.verbose:
        from utils.logger import set_log_level

        set_log_level(logger, "DEBUG")

    print("\n" + "=" * 70)
    print("[!] WHOIS Lookup - For Authorized Reconnaissance Only")
    print("=" * 70 + "\n")

    # Create lookup tool
    lookup = WHOISLookup(config)

    # Single domain lookup
    if args.domain:
        results = lookup.run(args.domain, not args.no_parse)

        if "error" in results:
            print(f"\n[-] Error: {results['error']}")
            return 1

        # Print summary
        if "parsed" in results:
            parsed = results["parsed"]
            print(f"\n[+] WHOIS Information for {results['domain']}:")
            print(f"    Registrar: {parsed.get('registrar', 'N/A')}")
            print(f"    Creation Date: {parsed.get('creation_date', 'N/A')}")
            print(f"    Expiration Date: {parsed.get('expiration_date', 'N/A')}")
            print(f"    Updated Date: {parsed.get('updated_date', 'N/A')}")
            print(f"    DNSSEC: {parsed.get('dnssec', 'N/A')}")

            if parsed.get("name_servers"):
                print("\n[+] Name Servers:")
                for ns in parsed["name_servers"]:
                    print(f"    - {ns}")

            if parsed.get("status"):
                print("\n[+] Status:")
                for status in parsed["status"]:
                    print(f"    - {status}")

        print(f"\n[+] Raw WHOIS data ({len(results['raw'])} bytes)")

    # Bulk lookup
    elif args.file:
        try:
            with open(args.file) as f:
                domains = [line.strip() for line in f if line.strip()]

            print(f"[*] Loaded {len(domains)} domains from {args.file}")
            results = lookup.bulk_lookup(domains)

            # Print summary
            print("\n[+] Bulk Lookup Summary:")
            print(f"    Total Domains: {len(domains)}")
            print(f"    Successful: {sum(1 for r in results.values() if 'error' not in r)}")
            print(f"    Failed: {sum(1 for r in results.values() if 'error' in r)}")

        except FileNotFoundError:
            print(f"\n[-] Error: File {args.file} not found")
            return 1
        except Exception as e:
            print(f"\n[-] Error: {e}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
