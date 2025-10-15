"""
Unit tests for exploitation/reverse_shell.py module.
"""

import pytest
from exploitation.reverse_shell import ReverseShellGenerator


class TestReverseShellGenerator:
    """Tests for ReverseShellGenerator class."""

    def test_initialization(self):
        """Test ReverseShellGenerator initialization."""
        generator = ReverseShellGenerator()

        assert generator is not None
        assert len(generator.payloads) > 0

    def test_generate_bash_shell(self):
        """Test generating bash reverse shell."""
        generator = ReverseShellGenerator()
        payload = generator.generate("192.168.1.100", 4444, "bash")

        assert payload is not None
        assert "192.168.1.100" in payload
        assert "4444" in payload
        assert "bash" in payload.lower()

    def test_generate_python_shell(self):
        """Test generating python reverse shell."""
        generator = ReverseShellGenerator()
        payload = generator.generate("192.168.1.100", 4444, "python")

        assert payload is not None
        assert "192.168.1.100" in payload
        assert "4444" in payload
        assert "socket" in payload

    def test_generate_powershell_shell(self):
        """Test generating powershell reverse shell."""
        generator = ReverseShellGenerator()
        payload = generator.generate("192.168.1.100", 4444, "powershell")

        assert payload is not None
        assert "192.168.1.100" in payload
        assert "4444" in payload
        assert "powershell" in payload.lower()

    def test_generate_netcat_shell(self):
        """Test generating netcat reverse shell."""
        generator = ReverseShellGenerator()
        payload = generator.generate("192.168.1.100", 4444, "nc")

        assert payload is not None
        assert "192.168.1.100" in payload
        assert "4444" in payload

    def test_generate_invalid_type(self):
        """Test generating with invalid shell type."""
        generator = ReverseShellGenerator()
        payload = generator.generate("192.168.1.100", 4444, "invalid")

        assert payload is None
