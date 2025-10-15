#!/usr/bin/env python3
"""
Subdomain Enumerator - Multi-Source Subdomain Discovery

Discovers subdomains using DNS brute-force, certificate transparency, and wordlists.

[!] AUTHORIZATION REQUIRED: Only use on authorized domains.

Usage:
    python subdomain_enum.py --domain <domain> [options]

Examples:
    # Basic subdomain enumeration
    python subdomain_enum.py --domain example.com

    # Use custom wordlist
    python subdomain_enum.py --domain example.com --wordlist subdomains.txt

    # Certificate transparency search
    python subdomain_enum.py --domain example.com --cert-transparency

Author: David Dashti
Date: 2025-10-15
MITRE ATT&CK: T1590.001 (Gather Victim Network Information: Domain Properties)
"""

import argparse
import sys
import dns.resolver
import requests
from typing import List, Set, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import get_logger
from utils.config import load_config
from utils.helpers import (
    validate_domain,
    check_authorization,
    RateLimiter,
    sanitize_filename
)

logger = get_logger(__name__)


# Common subdomain wordlist
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx",
    "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw",
    "admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov", "2tty",
    "vps", "govyty", "news", "1rer", "lms", "stage", "demo", "qa", "prod"
]


class SubdomainEnumerator:
    """
    Subdomain enumeration tool using multiple discovery methods.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize subdomain enumerator.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or load_config()
        self.rate_limiter = RateLimiter(
            self.config.get("rate_limit", {}).get("requests_per_second", 10)
        )
        self.found_subdomains: Set[str] = set()
        logger.info(f"Initialized {self.__class__.__name__}")

    def dns_bruteforce(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None
    ) -> Set[str]:
        """
        Brute-force subdomains using DNS queries.

        Args:
            domain: Target domain
            wordlist: Optional custom wordlist

        Returns:
            Set of discovered subdomains
        """
        if wordlist is None:
            wordlist = COMMON_SUBDOMAINS

        found = set()
        logger.info(f"Starting DNS brute-force with {len(wordlist)} subdomains")

        def check_subdomain(subdomain_name: str) -> Optional[str]:
            """Check if subdomain exists."""
            self.rate_limiter.wait()
            full_domain = f"{subdomain_name}.{domain}"

            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                answers = resolver.resolve(full_domain, "A")

                if answers:
                    logger.debug(f"Found: {full_domain}")
                    return full_domain

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            except Exception as e:
                logger.debug(f"Error checking {full_domain}: {e}")

            return None

        # Use threading for parallel DNS queries
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.add(result)
                    print(f"[+] Found: {result}")

        logger.info(f"DNS brute-force found {len(found)} subdomains")
        return found

    def cert_transparency_search(self, domain: str) -> Set[str]:
        """
        Search certificate transparency logs for subdomains.

        Args:
            domain: Target domain

        Returns:
            Set of discovered subdomains
        """
        found = set()
        logger.info("Searching certificate transparency logs")

        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            timeout = self.config.get("timeouts", {}).get("connection", 10)

            response = requests.get(url, timeout=timeout)

            if response.status_code == 200:
                certs = response.json()

                for cert in certs:
                    name_value = cert.get("name_value", "")
                    # Split by newlines (crt.sh returns multiple names per cert)
                    for subdomain in name_value.split("\n"):
                        subdomain = subdomain.strip().lower()
                        # Filter wildcards and only include target domain
                        if "*" not in subdomain and subdomain.endswith(domain):
                            found.add(subdomain)
                            logger.debug(f"Found from cert: {subdomain}")

                logger.info(f"Certificate transparency found {len(found)} subdomains")

        except Exception as e:
            logger.error(f"Certificate transparency search failed: {e}")

        return found

    def dns_dumpster_search(self, domain: str) -> Set[str]:
        """
        Search DNSDumpster for subdomains (passive).

        Args:
            domain: Target domain

        Returns:
            Set of discovered subdomains
        """
        # Note: DNSDumpster requires CSRF token and session handling
        # This is a simplified version - full implementation would need more work
        logger.info("DNSDumpster integration not yet implemented")
        return set()

    def run(
        self,
        domain: str,
        wordlist_file: Optional[str] = None,
        use_cert_transparency: bool = True,
        use_dns_bruteforce: bool = True
    ) -> Dict[str, Any]:
        """
        Execute subdomain enumeration.

        Args:
            domain: Target domain
            wordlist_file: Optional path to subdomain wordlist
            use_cert_transparency: Use certificate transparency logs
            use_dns_bruteforce: Use DNS brute-force

        Returns:
            Enumeration results
        """
        # Authorization check
        if not check_authorization(domain, self.config):
            logger.error(f"Domain {domain} not authorized")
            return {"error": "Not authorized"}

        # Validate domain
        if not validate_domain(domain):
            logger.error(f"Invalid domain: {domain}")
            return {"error": "Invalid domain"}

        logger.info(f"Starting subdomain enumeration for {domain}")
        print(f"\n[*] Enumerating subdomains for {domain}")

        self.found_subdomains.clear()

        # Certificate Transparency
        if use_cert_transparency:
            print("[*] Searching certificate transparency logs...")
            cert_subdomains = self.cert_transparency_search(domain)
            self.found_subdomains.update(cert_subdomains)

        # DNS Brute-force
        if use_dns_bruteforce:
            print(f"\n[*] Starting DNS brute-force...")
            wordlist = None

            if wordlist_file:
                try:
                    with open(wordlist_file, "r") as f:
                        wordlist = [line.strip() for line in f if line.strip()]
                    logger.info(f"Loaded {len(wordlist)} subdomains from wordlist")
                except Exception as e:
                    logger.error(f"Error loading wordlist: {e}")
                    wordlist = None

            dns_subdomains = self.dns_bruteforce(domain, wordlist)
            self.found_subdomains.update(dns_subdomains)

        results = {
            "domain": domain,
            "subdomains": sorted(list(self.found_subdomains)),
            "total_found": len(self.found_subdomains)
        }

        logger.info(f"Enumeration complete: {results['total_found']} subdomains found")
        self._save_results(results)

        return results

    def _save_results(self, results: Dict[str, Any]) -> None:
        """
        Save enumeration results to output directory.

        Args:
            results: Results dictionary to save
        """
        import json
        from pathlib import Path
        from datetime import datetime

        output_dir = Path(self.config.get("output", {}).get("directory", "output"))
        output_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_safe = sanitize_filename(results["domain"])
        filename = f"subdomains_{domain_safe}_{timestamp}.json"
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
        description="Subdomain Enumerator - Multi-Source Subdomain Discovery\n"
                    "[!] For authorized reconnaissance only",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--domain",
        required=True,
        help="Target domain"
    )

    parser.add_argument(
        "--wordlist",
        help="Path to subdomain wordlist file"
    )

    parser.add_argument(
        "--cert-transparency",
        action="store_true",
        default=True,
        help="Search certificate transparency logs (default: enabled)"
    )

    parser.add_argument(
        "--no-bruteforce",
        action="store_true",
        help="Disable DNS brute-force"
    )

    parser.add_argument(
        "--config",
        help="Path to configuration file"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config) if args.config else load_config()

    # Set log level
    if args.verbose:
        from utils.logger import set_log_level
        set_log_level(logger, "DEBUG")

    print("\n" + "=" * 70)
    print("[!] Subdomain Enumerator - For Authorized Reconnaissance Only")
    print("=" * 70)

    # Create enumerator
    enumerator = SubdomainEnumerator(config)

    # Run enumeration
    results = enumerator.run(
        args.domain,
        args.wordlist,
        args.cert_transparency,
        not args.no_bruteforce
    )

    if "error" in results:
        print(f"\n[-] Error: {results['error']}")
        return 1

    # Print summary
    print(f"\n[+] Enumeration Summary:")
    print(f"    Domain: {results['domain']}")
    print(f"    Subdomains Found: {results['total_found']}")

    if results["subdomains"]:
        print(f"\n[+] Discovered Subdomains:")
        for subdomain in results["subdomains"]:
            print(f"    - {subdomain}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
