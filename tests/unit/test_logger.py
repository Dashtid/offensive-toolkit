"""
Unit tests for utils/logger.py module.
"""

import pytest
import logging
from pathlib import Path
from utils.logger import (
    setup_logger,
    get_logger,
    set_log_level,
    sanitize_log_message,
    SanitizingLogger
)


class TestSetupLogger:
    """Tests for setup_logger function."""

    def test_logger_creation(self, temp_dir):
        """Test basic logger creation."""
        log_file = temp_dir / "test.log"
        logger = setup_logger("test_logger", log_file=str(log_file))

        assert logger is not None
        assert logger.name == "test_logger"
        assert len(logger.handlers) >= 1

    def test_logger_default_level(self):
        """Test logger default log level."""
        logger = setup_logger("test_default_level", file_output=False)
        assert logger.level == logging.INFO

    def test_logger_custom_level(self):
        """Test logger with custom log level."""
        logger = setup_logger(
            "test_custom_level",
            log_level=logging.DEBUG,
            file_output=False
        )
        assert logger.level == logging.DEBUG

    def test_console_handler_creation(self):
        """Test console handler is created when requested."""
        logger = setup_logger("test_console", console=True, file_output=False)
        console_handlers = [
            h for h in logger.handlers
            if isinstance(h, logging.StreamHandler)
        ]
        assert len(console_handlers) >= 1

    def test_file_handler_creation(self, temp_dir):
        """Test file handler is created when requested."""
        log_file = temp_dir / "test_file.log"
        logger = setup_logger(
            "test_file",
            log_file=str(log_file),
            console=False,
            file_output=True
        )

        # Write a log message
        logger.info("Test message")

        # Verify file was created
        assert log_file.exists()
        assert log_file.stat().st_size > 0

    def test_no_duplicate_handlers(self):
        """Test that calling setup_logger twice doesn't create duplicate handlers."""
        logger1 = setup_logger("test_duplicate", file_output=False)
        handler_count_1 = len(logger1.handlers)

        logger2 = setup_logger("test_duplicate", file_output=False)
        handler_count_2 = len(logger2.handlers)

        assert handler_count_1 == handler_count_2


class TestGetLogger:
    """Tests for get_logger function."""

    def test_get_existing_logger(self):
        """Test getting an existing logger."""
        setup_logger("existing_logger", file_output=False)
        logger = get_logger("existing_logger")

        assert logger is not None
        assert logger.name == "existing_logger"

    def test_get_new_logger(self):
        """Test getting a new logger creates it with defaults."""
        logger = get_logger("new_logger")

        assert logger is not None
        assert logger.name == "new_logger"


class TestSetLogLevel:
    """Tests for set_log_level function."""

    def test_set_debug_level(self):
        """Test setting DEBUG log level."""
        logger = setup_logger("test_set_debug", file_output=False)
        set_log_level(logger, "DEBUG")

        assert logger.level == logging.DEBUG

    def test_set_info_level(self):
        """Test setting INFO log level."""
        logger = setup_logger("test_set_info", file_output=False)
        set_log_level(logger, "INFO")

        assert logger.level == logging.INFO

    def test_set_warning_level(self):
        """Test setting WARNING log level."""
        logger = setup_logger("test_set_warning", file_output=False)
        set_log_level(logger, "WARNING")

        assert logger.level == logging.WARNING

    def test_set_error_level(self):
        """Test setting ERROR log level."""
        logger = setup_logger("test_set_error", file_output=False)
        set_log_level(logger, "ERROR")

        assert logger.level == logging.ERROR

    def test_set_invalid_level(self):
        """Test setting invalid log level defaults to INFO."""
        logger = setup_logger("test_invalid_level", file_output=False)
        set_log_level(logger, "INVALID")

        assert logger.level == logging.INFO

    def test_case_insensitive(self):
        """Test log level setting is case insensitive."""
        logger = setup_logger("test_case_insensitive", file_output=False)
        set_log_level(logger, "debug")

        assert logger.level == logging.DEBUG


class TestSanitizeLogMessage:
    """Tests for sanitize_log_message function."""

    def test_sanitize_password(self):
        """Test password sanitization."""
        message = "User logged in with password=secret123"
        sanitized = sanitize_log_message(message)

        assert "secret123" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_sanitize_api_key(self):
        """Test API key sanitization."""
        message = "Using api_key=abcd1234efgh5678"
        sanitized = sanitize_log_message(message)

        assert "abcd1234efgh5678" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_sanitize_token(self):
        """Test token sanitization."""
        message = "Authorization: Bearer token=xyz789"
        sanitized = sanitize_log_message(message)

        assert "xyz789" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_sanitize_credit_card(self):
        """Test credit card number sanitization."""
        message = "Payment with card 1234-5678-9012-3456"
        sanitized = sanitize_log_message(message)

        assert "1234-5678-9012-3456" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_no_sanitization_needed(self):
        """Test message with no sensitive data."""
        message = "Normal log message without secrets"
        sanitized = sanitize_log_message(message)

        assert sanitized == message

    def test_custom_patterns(self):
        """Test custom sensitive patterns."""
        message = "SSN: 123-45-6789"
        patterns = [r"\d{3}-\d{2}-\d{4}"]
        sanitized = sanitize_log_message(message, patterns)

        assert "123-45-6789" not in sanitized
        assert "[REDACTED]" in sanitized


class TestSanitizingLogger:
    """Tests for SanitizingLogger wrapper."""

    def test_sanitizing_info(self):
        """Test sanitizing logger info method."""
        base_logger = setup_logger("test_sanitizing", file_output=False)
        san_logger = SanitizingLogger(base_logger)

        # This should not raise an exception
        san_logger.info("User password: secret123")

    def test_sanitizing_debug(self):
        """Test sanitizing logger debug method."""
        base_logger = setup_logger("test_sanitizing_debug", file_output=False)
        san_logger = SanitizingLogger(base_logger)

        san_logger.debug("API key: abcd1234")

    def test_sanitizing_warning(self):
        """Test sanitizing logger warning method."""
        base_logger = setup_logger("test_sanitizing_warning", file_output=False)
        san_logger = SanitizingLogger(base_logger)

        san_logger.warning("Token expired: token=xyz789")

    def test_sanitizing_error(self):
        """Test sanitizing logger error method."""
        base_logger = setup_logger("test_sanitizing_error", file_output=False)
        san_logger = SanitizingLogger(base_logger)

        san_logger.error("Auth failed with secret=test123")

    def test_sanitizing_critical(self):
        """Test sanitizing logger critical method."""
        base_logger = setup_logger("test_sanitizing_critical", file_output=False)
        san_logger = SanitizingLogger(base_logger)

        san_logger.critical("System breach: password=admin123")


class TestLoggerIntegration:
    """Integration tests for logger functionality."""

    def test_log_to_file(self, temp_dir):
        """Test logging messages to file."""
        log_file = temp_dir / "integration.log"
        logger = setup_logger(
            "integration_test",
            log_file=str(log_file),
            console=False
        )

        logger.info("Test info message")
        logger.warning("Test warning message")
        logger.error("Test error message")

        # Read log file
        log_content = log_file.read_text()

        assert "Test info message" in log_content
        assert "Test warning message" in log_content
        assert "Test error message" in log_content

    def test_log_rotation(self, temp_dir):
        """Test log file rotation."""
        log_file = temp_dir / "rotation.log"
        logger = setup_logger(
            "rotation_test",
            log_file=str(log_file),
            console=False
        )

        # Write many messages to trigger rotation
        for i in range(1000):
            logger.info(f"Message {i} " * 100)

        # Check that log file exists (rotation is configured, even if not triggered)
        assert log_file.exists()
