"""
Unit tests for utils/helpers.py module.
"""

import time

from utils.helpers import (
    RateLimiter,
    check_authorization,
    format_bytes,
    is_target_authorized,
    load_authorized_targets,
    sanitize_filename,
    validate_cidr,
    validate_domain,
    validate_ip,
    validate_target,
    validate_url,
)


class TestValidateIP:
    """Tests for validate_ip function."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.0.0.1") is True
        assert validate_ip("8.8.8.8") is True

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        assert validate_ip("2001:db8::1") is True
        assert validate_ip("::1") is True
        assert validate_ip("fe80::1") is True

    def test_invalid_ip(self):
        """Test invalid IP addresses."""
        assert validate_ip("256.1.1.1") is False
        assert validate_ip("192.168.1") is False
        assert validate_ip("not.an.ip.address") is False
        assert validate_ip("") is False


class TestValidateCIDR:
    """Tests for validate_cidr function."""

    def test_valid_cidr(self):
        """Test valid CIDR notation."""
        assert validate_cidr("192.168.1.0/24") is True
        assert validate_cidr("10.0.0.0/8") is True
        assert validate_cidr("172.16.0.0/12") is True

    def test_valid_cidr_ipv6(self):
        """Test valid IPv6 CIDR notation."""
        assert validate_cidr("2001:db8::/32") is True
        assert validate_cidr("fe80::/10") is True

    def test_invalid_cidr(self):
        """Test invalid CIDR notation."""
        assert validate_cidr("192.168.1.1") is False
        assert validate_cidr("10.0.0.0/33") is False
        assert validate_cidr("not/24") is False


class TestValidateDomain:
    """Tests for validate_domain function."""

    def test_valid_domain(self):
        """Test valid domain names."""
        assert validate_domain("example.com") is True
        assert validate_domain("sub.example.com") is True
        assert validate_domain("test-site.co.uk") is True

    def test_invalid_domain(self):
        """Test invalid domain names."""
        assert validate_domain("invalid") is False
        assert validate_domain("") is False
        assert validate_domain("192.168.1.1") is False
        assert validate_domain("-invalid.com") is False


class TestValidateURL:
    """Tests for validate_url function."""

    def test_valid_url(self):
        """Test valid URLs."""
        assert validate_url("https://example.com") is True
        assert validate_url("http://example.com/path") is True
        assert validate_url("https://example.com:8080") is True

    def test_invalid_url(self):
        """Test invalid URLs."""
        assert validate_url("not a url") is False
        assert validate_url("example.com") is False
        assert validate_url("") is False
        assert validate_url("ftp://") is False


class TestValidateTarget:
    """Tests for validate_target function."""

    def test_validate_ip_type(self):
        """Test validating IP addresses."""
        assert validate_target("192.168.1.1", "ip") is True
        assert validate_target("example.com", "ip") is False

    def test_validate_domain_type(self):
        """Test validating domain names."""
        assert validate_target("example.com", "domain") is True
        assert validate_target("192.168.1.1", "domain") is False

    def test_validate_url_type(self):
        """Test validating URLs."""
        assert validate_target("https://example.com", "url") is True
        assert validate_target("example.com", "url") is False

    def test_validate_cidr_type(self):
        """Test validating CIDR notation."""
        assert validate_target("192.168.1.0/24", "cidr") is True
        assert validate_target("192.168.1.1", "cidr") is False

    def test_validate_auto_detection(self):
        """Test auto-detection of target type."""
        assert validate_target("192.168.1.1", "auto") is True
        assert validate_target("example.com", "auto") is True
        assert validate_target("https://example.com", "auto") is True
        assert validate_target("10.0.0.0/8", "auto") is True
        assert validate_target("invalid!@#", "auto") is False

    def test_validate_empty_target(self):
        """Test validation with empty target."""
        assert validate_target("", "auto") is False
        assert validate_target(None, "auto") is False


class TestLoadAuthorizedTargets:
    """Tests for load_authorized_targets function."""

    def test_load_targets_file(self, temp_dir):
        """Test loading targets from file."""
        targets_file = temp_dir / "targets.txt"
        targets_file.write_text("""
# Comment line
192.168.1.0/24
example.com
10.0.0.1
        """)

        targets = load_authorized_targets(str(targets_file))

        assert len(targets) == 3
        assert "192.168.1.0/24" in targets
        assert "example.com" in targets
        assert "10.0.0.1" in targets

    def test_load_nonexistent_file(self):
        """Test loading from nonexistent file."""
        targets = load_authorized_targets("nonexistent.txt")

        assert targets == []

    def test_ignore_comments_and_blank_lines(self, temp_dir):
        """Test comments and blank lines are ignored."""
        targets_file = temp_dir / "targets.txt"
        targets_file.write_text("""
# This is a comment
192.168.1.0/24

example.com  # Inline comment
        """)

        targets = load_authorized_targets(str(targets_file))

        assert len(targets) == 2
        assert "192.168.1.0/24" in targets
        assert "example.com" in targets


class TestIsTargetAuthorized:
    """Tests for is_target_authorized function."""

    def test_exact_match(self):
        """Test exact target match."""
        authorized = ["192.168.1.10", "example.com"]

        assert is_target_authorized("192.168.1.10", authorized) is True
        assert is_target_authorized("example.com", authorized) is True
        assert is_target_authorized("other.com", authorized) is False

    def test_cidr_match(self):
        """Test CIDR network match."""
        authorized = ["192.168.1.0/24", "10.0.0.0/8"]

        assert is_target_authorized("192.168.1.10", authorized) is True
        assert is_target_authorized("192.168.1.50", authorized) is True
        assert is_target_authorized("10.5.10.1", authorized) is True
        assert is_target_authorized("172.16.0.1", authorized) is False

    def test_wildcard_domain_match(self):
        """Test wildcard domain match."""
        authorized = ["*.example.com"]

        assert is_target_authorized("sub.example.com", authorized) is True
        assert is_target_authorized("deep.sub.example.com", authorized) is True
        assert is_target_authorized("example.com", authorized) is False
        assert is_target_authorized("other.com", authorized) is False

    def test_subdomain_match(self):
        """Test subdomain matching."""
        authorized = ["example.com"]

        assert is_target_authorized("sub.example.com", authorized) is True
        assert is_target_authorized("example.com", authorized) is True
        assert is_target_authorized("other.com", authorized) is False

    def test_url_extraction(self):
        """Test extracting host from URL."""
        authorized = ["example.com"]

        assert is_target_authorized("https://example.com/path", authorized) is True
        assert is_target_authorized("http://example.com:8080", authorized) is True


class TestCheckAuthorization:
    """Tests for check_authorization function."""

    def test_authorized_target(self, test_config, temp_dir):
        """Test checking authorized target."""
        # Create authorized targets file
        targets_file = temp_dir / "authorized.txt"
        targets_file.write_text("192.168.1.0/24\n")

        test_config["authorization"]["scope_file"] = str(targets_file)
        test_config["authorization"]["require_confirmation"] = False

        result = check_authorization("192.168.1.10", test_config, interactive=False)

        assert result is True

    def test_unauthorized_target(self, test_config, temp_dir):
        """Test checking unauthorized target without confirmation."""
        targets_file = temp_dir / "authorized.txt"
        targets_file.write_text("192.168.1.0/24\n")

        test_config["authorization"]["scope_file"] = str(targets_file)
        test_config["authorization"]["require_confirmation"] = False

        result = check_authorization("10.0.0.1", test_config, interactive=False)

        assert result is False


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_rate_limiter_initialization(self):
        """Test rate limiter initialization."""
        limiter = RateLimiter(requests_per_second=10)

        assert limiter.rate == 10
        assert limiter.interval == 0.1

    def test_rate_limiter_wait(self):
        """Test rate limiter enforces delays."""
        limiter = RateLimiter(requests_per_second=10)

        start_time = time.time()
        limiter.wait()
        limiter.wait()
        limiter.wait()
        elapsed_time = time.time() - start_time

        # Should take at least 0.2 seconds for 3 requests at 10 req/s
        assert elapsed_time >= 0.2

    def test_rate_limiter_set_rate(self):
        """Test changing rate limit."""
        limiter = RateLimiter(requests_per_second=10)
        limiter.set_rate(20)

        assert limiter.rate == 20
        assert limiter.interval == 0.05

    def test_rate_limiter_high_rate(self):
        """Test rate limiter with high request rate."""
        limiter = RateLimiter(requests_per_second=100)

        start_time = time.time()
        for _ in range(10):
            limiter.wait()
        elapsed_time = time.time() - start_time

        # Should take at least 0.09 seconds for 10 requests at 100 req/s
        assert elapsed_time >= 0.09


class TestFormatBytes:
    """Tests for format_bytes function."""

    def test_format_bytes(self):
        """Test byte formatting."""
        assert format_bytes(0) == "0.00 B"
        assert format_bytes(1024) == "1.00 KB"
        assert format_bytes(1048576) == "1.00 MB"
        assert format_bytes(1073741824) == "1.00 GB"

    def test_format_bytes_precision(self):
        """Test byte formatting precision."""
        assert format_bytes(1536) == "1.50 KB"
        assert format_bytes(1572864) == "1.50 MB"


class TestSanitizeFilename:
    """Tests for sanitize_filename function."""

    def test_sanitize_dangerous_chars(self):
        """Test sanitizing dangerous characters."""
        filename = 'test<>:"/\\|?*.txt'
        sanitized = sanitize_filename(filename)

        assert "<" not in sanitized
        assert ">" not in sanitized
        assert ":" not in sanitized
        assert '"' not in sanitized
        assert "/" not in sanitized
        assert "\\" not in sanitized
        assert "|" not in sanitized
        assert "?" not in sanitized
        assert "*" not in sanitized

    def test_sanitize_preserves_safe_chars(self):
        """Test sanitizing preserves safe characters."""
        filename = "test_file-123.txt"
        sanitized = sanitize_filename(filename)

        assert sanitized == filename

    def test_sanitize_empty_filename(self):
        """Test sanitizing empty filename."""
        filename = ""
        sanitized = sanitize_filename(filename)

        assert sanitized == "unnamed_file"

    def test_sanitize_dots_and_spaces(self):
        """Test sanitizing leading/trailing dots and spaces."""
        filename = "  ...test_file...  "
        sanitized = sanitize_filename(filename)

        assert not sanitized.startswith(".")
        assert not sanitized.endswith(".")
        assert not sanitized.startswith(" ")
        assert not sanitized.endswith(" ")
