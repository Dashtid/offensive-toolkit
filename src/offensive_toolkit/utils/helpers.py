#!/usr/bin/env python3
"""
Helper Functions Module

Common utility functions for authorization checking, validation, and rate limiting.

Author: David Dashti
Date: 2025-10-15
"""

import ipaddress
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from offensive_toolkit.utils.logger import get_logger

logger = get_logger(__name__)


def validate_target(target: str, target_type: str = "auto") -> bool:
    """
    Validate target format (IP, domain, URL, CIDR, etc.).

    Args:
        target: Target string to validate
        target_type: Type of target ("ip", "domain", "url", "cidr", "auto")

    Returns:
        True if valid, False otherwise

    Example:
        >>> validate_target("192.168.1.1", "ip")
        True
        >>> validate_target("example.com", "domain")
        True
        >>> validate_target("https://example.com/path", "url")
        True
    """
    if not target or not isinstance(target, str):
        return False

    if target_type == "auto":
        # Try to auto-detect target type
        if validate_ip(target) or validate_cidr(target):
            return True
        if validate_domain(target):
            return True
        if validate_url(target):
            return True
        return False

    validators = {
        "ip": validate_ip,
        "domain": validate_domain,
        "url": validate_url,
        "cidr": validate_cidr,
    }

    validator = validators.get(target_type)
    if validator:
        return validator(target)

    logger.warning(f"Unknown target type: {target_type}")
    return False


def validate_ip(ip: str) -> bool:
    """
    Validate IPv4 or IPv6 address.

    Args:
        ip: IP address string

    Returns:
        True if valid IP address

    Example:
        >>> validate_ip("192.168.1.1")
        True
        >>> validate_ip("2001:db8::1")
        True
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """
    Validate CIDR notation network.

    Args:
        cidr: CIDR notation string (e.g., "192.168.1.0/24")

    Returns:
        True if valid CIDR notation

    Example:
        >>> validate_cidr("192.168.1.0/24")
        True
        >>> validate_cidr("10.0.0.0/8")
        True
    """
    # CIDR notation must contain a slash
    if "/" not in cidr:
        return False
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """
    Validate domain name format.

    Args:
        domain: Domain name string

    Returns:
        True if valid domain name

    Example:
        >>> validate_domain("example.com")
        True
        >>> validate_domain("sub.example.co.uk")
        True
    """
    # Simple domain validation regex
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(domain_regex, domain))


def validate_url(url: str) -> bool:
    """
    Validate URL format.

    Args:
        url: URL string

    Returns:
        True if valid URL

    Example:
        >>> validate_url("https://example.com/path")
        True
        >>> validate_url("http://192.168.1.1:8080")
        True
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def check_authorization(
    target: str, config: dict[str, Any] | None = None, interactive: bool = True
) -> bool:
    """
    Check if target is authorized for testing.

    Checks against authorized_targets.txt and optionally prompts for confirmation.

    Args:
        target: Target to check (IP, domain, URL, CIDR)
        config: Configuration dictionary
        interactive: Prompt user for confirmation if True

    Returns:
        True if authorized, False otherwise

    Example:
        >>> check_authorization("192.168.1.1")
        [!] Target 192.168.1.1 not in authorized targets
        [?] Do you have authorization to test this target? (yes/no): yes
        True
    """
    from offensive_toolkit.utils.config import load_config

    if config is None:
        config = load_config()

    # Get authorized targets file path
    targets_file = config.get("authorization", {}).get(
        "scope_file", "config/authorized_targets.txt"
    )

    # Load authorized targets
    authorized_targets = load_authorized_targets(targets_file)

    # Check if target matches any authorized target
    if is_target_authorized(target, authorized_targets):
        logger.info(f"Target {target} is authorized")
        return True

    # Not in authorized list
    logger.warning(f"Target {target} not in authorized targets file")

    # If interactive confirmation is enabled
    require_confirmation = config.get("authorization", {}).get("require_confirmation", True)

    if interactive and require_confirmation:
        return prompt_authorization(target)

    return False


def load_authorized_targets(file_path: str) -> list[str]:
    """
    Load authorized targets from file.

    Args:
        file_path: Path to authorized targets file

    Returns:
        List of authorized target patterns

    Example:
        >>> targets = load_authorized_targets("config/authorized_targets.txt")
        >>> print(targets)
        ['192.168.1.0/24', 'testlab.example.com']
    """
    targets = []
    targets_file = Path(file_path)

    if not targets_file.exists():
        logger.warning(f"Authorized targets file not found: {file_path}")
        return targets

    try:
        with open(targets_file) as f:
            for line in f:
                # Remove comments and whitespace
                line = line.split("#")[0].strip()
                if line:
                    targets.append(line)

        logger.debug(f"Loaded {len(targets)} authorized targets from {file_path}")

    except Exception as e:
        logger.error(f"Error loading authorized targets: {e}")

    return targets


def is_target_authorized(target: str, authorized_targets: list[str]) -> bool:
    """
    Check if target matches any authorized target pattern.

    Args:
        target: Target to check
        authorized_targets: List of authorized target patterns

    Returns:
        True if target matches any authorized pattern

    Example:
        >>> authorized = ['192.168.1.0/24', 'example.com']
        >>> is_target_authorized('192.168.1.10', authorized)
        True
    """
    # Extract hostname/IP from URL if necessary
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        target = parsed.netloc.split(":")[0]  # Remove port

    for authorized in authorized_targets:
        # Exact match
        if target == authorized:
            return True

        # CIDR match
        if "/" in authorized:
            try:
                network = ipaddress.ip_network(authorized, strict=False)
                target_ip = ipaddress.ip_address(target)
                if target_ip in network:
                    return True
            except ValueError:
                continue

        # Domain wildcard match (*.example.com matches sub.example.com)
        if authorized.startswith("*."):
            domain_suffix = authorized[2:]
            # Wildcard should match subdomains only, not the root domain
            if target.endswith(domain_suffix) and target != domain_suffix:
                return True

        # Subdomain match (example.com matches sub.example.com)
        if target.endswith(f".{authorized}") or target == authorized:
            return True

    return False


def prompt_authorization(target: str) -> bool:
    """
    Prompt user for authorization confirmation.

    Args:
        target: Target being tested

    Returns:
        True if user confirms authorization, False otherwise

    Example:
        >>> prompt_authorization("192.168.1.1")
        [!] WARNING: Target 192.168.1.1 is not in your authorized targets list
        [?] Do you have written authorization to test this target? (yes/no): yes
        True
    """
    print(f"\n[!] WARNING: Target {target} is not in your authorized targets list")
    print("[!] Unauthorized access to computer systems is illegal")
    print("[!] Ensure you have WRITTEN AUTHORIZATION before proceeding\n")

    response = input("[?] Do you have written authorization to test this target? (yes/no): ")

    if response.lower() in ("yes", "y"):
        print("[+] User confirmed authorization")
        logger.warning(f"User confirmed authorization for {target}")
        return True
    print("[-] Authorization not confirmed. Exiting.")
    logger.info(f"User declined authorization for {target}")
    return False


class RateLimiter:
    """
    Token bucket rate limiter for network operations.

    Limits requests per second to prevent abuse and detection.

    Example:
        >>> limiter = RateLimiter(requests_per_second=10)
        >>> for target in targets:
        ...     limiter.wait()
        ...     scan(target)
    """

    def __init__(self, requests_per_second: float = 10.0):
        """
        Initialize rate limiter.

        Args:
            requests_per_second: Maximum requests per second
        """
        self.rate = requests_per_second
        self.interval = 1.0 / requests_per_second
        self.last_request = 0.0
        logger.debug(f"Rate limiter initialized: {requests_per_second} req/s")

    def wait(self) -> None:
        """
        Wait if necessary to maintain rate limit.

        Blocks execution until next request is allowed.
        """
        current_time = time.time()
        time_since_last = current_time - self.last_request

        if time_since_last < self.interval:
            sleep_time = self.interval - time_since_last
            time.sleep(sleep_time)

        self.last_request = time.time()

    def set_rate(self, requests_per_second: float) -> None:
        """
        Update rate limit.

        Args:
            requests_per_second: New rate limit
        """
        self.rate = requests_per_second
        self.interval = 1.0 / requests_per_second
        logger.debug(f"Rate limit updated: {requests_per_second} req/s")


def rate_limit(requests_per_second: float = 10.0):
    """
    Decorator for rate-limited functions.

    Args:
        requests_per_second: Maximum requests per second

    Example:
        >>> @rate_limit(requests_per_second=5)
        ... def scan_port(ip, port):
        ...     # Scanning logic here
        ...     pass
    """
    limiter = RateLimiter(requests_per_second)

    def decorator(func):
        def wrapper(*args, **kwargs):
            limiter.wait()
            return func(*args, **kwargs)

        return wrapper

    return decorator


def format_bytes(bytes_count: int) -> str:
    """
    Format byte count as human-readable string.

    Args:
        bytes_count: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 MB")

    Example:
        >>> format_bytes(1536000)
        '1.46 MB'
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing dangerous characters.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename safe for filesystem

    Example:
        >>> sanitize_filename("report_<script>alert()</script>.html")
        'report_scriptalertscript.html'
    """
    # Remove dangerous characters
    dangerous_chars = ["<", ">", ":", '"', "/", "\\", "|", "?", "*"]
    sanitized = filename

    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")

    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip(". ")

    # Ensure filename is not empty
    if not sanitized:
        sanitized = "unnamed_file"

    return sanitized


if __name__ == "__main__":
    # Test helper functions
    print("[*] Testing helper functions...\n")

    # Test validation
    print("[+] Testing validation:")
    print(f"  IP (192.168.1.1): {validate_target('192.168.1.1', 'ip')}")
    print(f"  Domain (example.com): {validate_target('example.com', 'domain')}")
    print(f"  URL (https://example.com): {validate_target('https://example.com', 'url')}")
    print(f"  CIDR (10.0.0.0/8): {validate_target('10.0.0.0/8', 'cidr')}")

    # Test rate limiter
    print("\n[+] Testing rate limiter (5 requests):")
    limiter = RateLimiter(requests_per_second=2)
    start = time.time()
    for i in range(5):
        limiter.wait()
        print(f"  Request {i + 1} at {time.time() - start:.2f}s")

    # Test byte formatting
    print("\n[+] Testing byte formatting:")
    print(f"  1536 bytes: {format_bytes(1536)}")
    print(f"  1048576 bytes: {format_bytes(1048576)}")

    # Test filename sanitization
    print("\n[+] Testing filename sanitization:")
    print("  Original: report_<script>.html")
    print(f"  Sanitized: {sanitize_filename('report_<script>.html')}")

    print("\n[+] Helper functions test complete")
