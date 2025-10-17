#!/usr/bin/env python3
"""
Port Scanner - Network Service Discovery

A rate-limited port scanner for discovering open ports and services on target systems.

[!] AUTHORIZATION REQUIRED: Only use on systems you have explicit permission to test.

Usage:
    python port_scanner.py --target <target> [options]

Examples:
    # Scan common ports on a single host
    python port_scanner.py --target 192.168.1.1

    # Scan specific port range
    python port_scanner.py --target 192.168.1.1 --ports 1-1000

    # Scan with custom rate limit
    python port_scanner.py --target 192.168.1.0/24 --rate-limit 5

Author: David Dashti
Date: 2025-10-15
MITRE ATT&CK: T1046 (Network Service Discovery)
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from utils.config import load_config
from utils.helpers import RateLimiter, check_authorization, sanitize_filename, validate_target
from utils.logger import get_logger

logger = get_logger(__name__)


# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


class PortScanner:
    """
    Network port scanner with rate limiting and service detection.

    Attributes:
        config (Dict[str, Any]): Configuration dictionary
        target (str): Target IP or hostname
        rate_limiter (RateLimiter): Rate limiting instance
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize the port scanner.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or load_config()
        self.rate_limiter = RateLimiter(
            self.config.get("rate_limit", {}).get("requests_per_second", 10)
        )
        logger.info(f"Initialized {self.__class__.__name__}")

    def scan_port(self, host: str, port: int, timeout: float = 1.0) -> tuple[int, bool, str]:
        """
        Scan a single port on a host.

        Args:
            host: Target hostname or IP
            port: Port number to scan
            timeout: Connection timeout in seconds

        Returns:
            Tuple of (port, is_open, service_name)
        """
        self.rate_limiter.wait()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            is_open = result == 0
            service = COMMON_PORTS.get(port, "Unknown")

            if is_open:
                logger.debug(f"Port {port} is open on {host} ({service})")

            return (port, is_open, service)

        except socket.gaierror:
            logger.error(f"Hostname {host} could not be resolved")
            return (port, False, "Error")
        except OSError as e:
            logger.debug(f"Connection error on port {port}: {e}")
            return (port, False, "Error")

    def scan_ports(
        self, host: str, ports: list[int], max_threads: int = 100
    ) -> dict[int, dict[str, Any]]:
        """
        Scan multiple ports on a host using threading.

        Args:
            host: Target hostname or IP
            ports: List of port numbers to scan
            max_threads: Maximum number of concurrent threads

        Returns:
            Dictionary mapping port numbers to scan results
        """
        results = {}
        logger.info(f"Scanning {len(ports)} ports on {host}")

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {executor.submit(self.scan_port, host, port): port for port in ports}

            completed = 0
            for future in as_completed(future_to_port):
                port, is_open, service = future.result()
                if is_open:
                    results[port] = {"status": "open", "service": service}
                    print(f"[+] {host}:{port} - {service} - OPEN")

                completed += 1
                if completed % 100 == 0:
                    logger.info(f"Progress: {completed}/{len(ports)} ports scanned")

        return results

    def run(self, target: str, port_range: str = "common") -> dict[str, Any]:
        """
        Execute the port scan against a target.

        Args:
            target: Target IP or hostname
            port_range: Port range specification ("common", "1-1000", "80,443,8080")

        Returns:
            Scan results dictionary
        """
        # Validate target format first
        if not validate_target(target, "auto"):
            logger.error(f"Invalid target format: {target}")
            return {"error": "Invalid target"}

        # Authorization check
        if not check_authorization(target, self.config):
            logger.error(f"Target {target} not authorized for testing")
            return {"error": "Not authorized"}

        logger.info(f"Starting port scan against {target}")
        logger.info(f"[!] Ensure you have authorization to scan {target}")

        # Parse port range
        ports = self._parse_port_range(port_range)
        if not ports:
            logger.error(f"Invalid port range: {port_range}")
            return {"error": "Invalid port range"}

        # Perform scan
        try:
            results = self.scan_ports(target, ports)

            summary = {
                "target": target,
                "total_ports_scanned": len(ports),
                "open_ports": len(results),
                "results": results,
            }

            logger.info(f"Scan complete: {len(results)} open ports found")
            self._save_results(summary)

            return summary

        except Exception as e:
            logger.error(f"Error during scan: {e!s}", exc_info=True)
            return {"error": str(e)}

    def _parse_port_range(self, port_range: str) -> list[int]:
        """
        Parse port range specification into list of ports.

        Args:
            port_range: Port range ("common", "1-65535", "80,443,8080")

        Returns:
            List of port numbers
        """
        if port_range.lower() == "common":
            return sorted(COMMON_PORTS.keys())

        if "-" in port_range:
            # Range: "1-1000"
            try:
                start, end = map(int, port_range.split("-"))
                return list(range(start, end + 1))
            except ValueError:
                logger.error(f"Invalid port range: {port_range}")
                return []

        if "," in port_range:
            # List: "80,443,8080"
            try:
                return [int(p.strip()) for p in port_range.split(",")]
            except ValueError:
                logger.error(f"Invalid port list: {port_range}")
                return []

        # Single port
        try:
            return [int(port_range)]
        except ValueError:
            logger.error(f"Invalid port: {port_range}")
            return []

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
        target_safe = sanitize_filename(results["target"])
        filename = f"portscan_{target_safe}_{timestamp}.json"
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
        description="Port Scanner - Network Service Discovery\n"
        "[!] For authorized security testing only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--target", required=True, help="Target IP address or hostname")

    parser.add_argument(
        "--ports", default="common", help="Port range (common, 1-65535, 80,443,8080)"
    )

    parser.add_argument(
        "--rate-limit", type=float, default=10.0, help="Maximum requests per second (default: 10)"
    )

    parser.add_argument("--config", help="Path to configuration file")

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config) if args.config else load_config()

    # Override rate limit if specified
    if args.rate_limit:
        config["rate_limit"]["requests_per_second"] = args.rate_limit

    # Set log level
    if args.verbose:
        from utils.logger import set_log_level

        set_log_level(logger, "DEBUG")

    # Print warning
    print("\n" + "=" * 70)
    print("[!] Port Scanner - For Authorized Security Testing Only")
    print("[!] Unauthorized port scanning may be illegal in your jurisdiction")
    print("[!] Ensure you have written permission before proceeding")
    print("=" * 70 + "\n")

    # Create and run scanner
    scanner = PortScanner(config)
    results = scanner.run(args.target, args.ports)

    if "error" in results:
        print(f"\n[-] Scan failed: {results['error']}")
        return 1

    # Print summary
    print("\n[+] Scan Summary:")
    print(f"    Target: {results['target']}")
    print(f"    Ports Scanned: {results['total_ports_scanned']}")
    print(f"    Open Ports: {results['open_ports']}")

    if results["open_ports"] > 0:
        print("\n[+] Open Ports:")
        for port, info in sorted(results["results"].items()):
            print(f"    {port:5d} - {info['service']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
