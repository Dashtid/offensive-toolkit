#!/usr/bin/env python3
"""
Directory Brute-Forcer - Web Path Discovery

Discovers hidden directories and files on web servers using wordlist-based enumeration.

[!] AUTHORIZATION REQUIRED: Only use on web applications you have permission to test.

Usage:
    python directory_bruteforcer.py --target <url> --wordlist <file>

Example:
    python directory_bruteforcer.py --target https://example.com --wordlist wordlists/common.txt

Author: David Dashti
Date: 2025-10-15
MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
"""

import argparse
import sys
from typing import Any
from urllib.parse import urljoin

import requests

from utils.config import load_config
from utils.helpers import RateLimiter, check_authorization, validate_target
from utils.logger import get_logger

logger = get_logger(__name__)


class DirectoryBruteforcer:
    """
    Web directory and file brute-forcing tool.

    [!] This is a TEMPLATE for educational purposes.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize the directory brute-forcer."""
        self.config = config or load_config()
        self.rate_limiter = RateLimiter(
            self.config.get("rate_limit", {}).get("requests_per_second", 10)
        )
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.config.get("user_agent", "Mozilla/5.0")})
        logger.info(f"Initialized {self.__class__.__name__}")

    def test_path(self, base_url: str, path: str) -> dict[str, Any] | None:
        """
        Test if a path exists on the web server.

        Args:
            base_url: Base URL (e.g., https://example.com)
            path: Path to test (e.g., /admin)

        Returns:
            Dictionary with status and details if found, None otherwise
        """
        self.rate_limiter.wait()
        url = urljoin(base_url, path)

        try:
            timeout = self.config.get("timeouts", {}).get("connection", 10)
            response = self.session.get(url, timeout=timeout, allow_redirects=False)

            # Consider 200, 204, 301, 302, 401, 403 as "interesting"
            if response.status_code in [200, 204, 301, 302, 401, 403]:
                return {
                    "url": url,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "redirect": response.headers.get("Location"),
                }

        except requests.RequestException as e:
            logger.debug(f"Error testing {url}: {e}")

        return None

    def run(self, target: str, wordlist_path: str) -> dict[str, Any]:
        """
        Execute directory brute-force attack.

        Args:
            target: Target URL
            wordlist_path: Path to wordlist file

        Returns:
            Dictionary with results
        """
        # Authorization check
        if not check_authorization(target, self.config):
            logger.error(f"Target {target} not authorized")
            return {"error": "Not authorized"}

        # Validate target
        if not validate_target(target, "url"):
            logger.error(f"Invalid URL: {target}")
            return {"error": "Invalid URL"}

        # Load wordlist
        wordlist = self._load_wordlist(wordlist_path)
        if not wordlist:
            return {"error": "Empty or invalid wordlist"}

        logger.info(f"Starting directory brute-force against {target}")
        logger.info(f"Testing {len(wordlist)} paths")

        results = []
        for i, path in enumerate(wordlist, 1):
            result = self.test_path(target, path)
            if result:
                results.append(result)
                print(f"[+] Found: {result['url']} (Status: {result['status_code']})")

            if i % 100 == 0:
                logger.info(f"Progress: {i}/{len(wordlist)} paths tested")

        summary = {
            "target": target,
            "paths_tested": len(wordlist),
            "paths_found": len(results),
            "results": results,
        }

        logger.info(f"Brute-force complete: {len(results)} paths found")
        return summary

    def _load_wordlist(self, wordlist_path: str) -> list[str]:
        """Load wordlist from file."""
        try:
            with open(wordlist_path) as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error loading wordlist: {e}")
            return []


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Directory Brute-Forcer - Web Path Discovery")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("--rate-limit", type=float, default=10.0, help="Requests per second")

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("[!] Directory Brute-Forcer - For Authorized Testing Only")
    print("=" * 70 + "\n")

    config = load_config()
    config["rate_limit"]["requests_per_second"] = args.rate_limit

    bruteforcer = DirectoryBruteforcer(config)
    results = bruteforcer.run(args.target, args.wordlist)

    if "error" in results:
        print(f"[-] Error: {results['error']}")
        return 1

    print("\n[+] Summary:")
    print(f"    Paths Tested: {results['paths_tested']}")
    print(f"    Paths Found: {results['paths_found']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
