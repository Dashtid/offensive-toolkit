#!/usr/bin/env python3
"""
Logging Utility Module

Centralized logging configuration for the Offensive Security Toolkit.
Provides consistent logging across all modules with file and console output.

Author: David Dashti
Date: 2025-10-15
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from logging.handlers import RotatingFileHandler


# Default configuration
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_FORMAT = "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_LOG_DIR = "logs"
DEFAULT_LOG_FILE = "toolkit.log"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5


def setup_logger(
    name: str = "offensive_toolkit",
    log_level: int = DEFAULT_LOG_LEVEL,
    log_file: Optional[str] = None,
    console: bool = True,
    file_output: bool = True,
) -> logging.Logger:
    """
    Set up and configure a logger with file and console handlers.

    Args:
        name: Logger name (typically __name__)
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (default: logs/toolkit.log)
        console: Enable console output
        file_output: Enable file output

    Returns:
        Configured logger instance

    Example:
        >>> logger = setup_logger(__name__)
        >>> logger.info("Tool initialized")
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Create formatter
    formatter = logging.Formatter(DEFAULT_LOG_FORMAT, DEFAULT_DATE_FORMAT)

    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler with rotation
    if file_output:
        if log_file is None:
            log_dir = Path(DEFAULT_LOG_DIR)
            log_dir.mkdir(exist_ok=True)
            log_file = str(log_dir / DEFAULT_LOG_FILE)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT,
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get an existing logger or create a new one with default settings.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.warning("Rate limit approaching")
    """
    logger = logging.getLogger(name)

    # If logger has no handlers, set it up
    if not logger.handlers:
        return setup_logger(name)

    return logger


def set_log_level(logger: logging.Logger, level: str) -> None:
    """
    Set the logging level for a logger.

    Args:
        logger: Logger instance
        level: Log level as string (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Example:
        >>> logger = get_logger(__name__)
        >>> set_log_level(logger, "DEBUG")
    """
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }

    numeric_level = level_map.get(level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    for handler in logger.handlers:
        handler.setLevel(numeric_level)


def sanitize_log_message(message: str, sensitive_patterns: Optional[list] = None) -> str:
    """
    Sanitize log messages to remove sensitive information.

    Args:
        message: Original log message
        sensitive_patterns: List of patterns to redact (default: common secrets)

    Returns:
        Sanitized log message

    Example:
        >>> sanitize_log_message("Password: secret123")
        'Password: [REDACTED]'
    """
    import re

    if sensitive_patterns is None:
        # Default patterns for common secrets
        sensitive_patterns = [
            r"password[=:]\s*\S+",
            r"api[_-]?key[=:]\s*\S+",
            r"token[=:]\s*\S+",
            r"secret[=:]\s*\S+",
            r"authorization[=:]\s*\S+",
            r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}",  # Credit card
        ]

    sanitized = message
    for pattern in sensitive_patterns:
        sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)

    return sanitized


class SanitizingLogger:
    """
    Logger wrapper that automatically sanitizes sensitive information.

    Example:
        >>> logger = SanitizingLogger(get_logger(__name__))
        >>> logger.info("User logged in with password: secret123")
        # Logs: "User logged in with [REDACTED]"
    """

    def __init__(self, logger: logging.Logger):
        """
        Initialize sanitizing logger wrapper.

        Args:
            logger: Base logger instance
        """
        self.logger = logger

    def debug(self, msg: str, *args, **kwargs):
        """Log debug message with sanitization."""
        self.logger.debug(sanitize_log_message(msg), *args, **kwargs)

    def info(self, msg: str, *args, **kwargs):
        """Log info message with sanitization."""
        self.logger.info(sanitize_log_message(msg), *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        """Log warning message with sanitization."""
        self.logger.warning(sanitize_log_message(msg), *args, **kwargs)

    def error(self, msg: str, *args, **kwargs):
        """Log error message with sanitization."""
        self.logger.error(sanitize_log_message(msg), *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs):
        """Log critical message with sanitization."""
        self.logger.critical(sanitize_log_message(msg), *args, **kwargs)


# Module-level logger for utility functions
_module_logger = setup_logger(__name__)


if __name__ == "__main__":
    # Test logging functionality
    test_logger = setup_logger("test")
    test_logger.debug("Debug message")
    test_logger.info("Info message")
    test_logger.warning("Warning message")
    test_logger.error("Error message")
    test_logger.critical("Critical message")

    # Test sanitization
    sanitizing_logger = SanitizingLogger(test_logger)
    sanitizing_logger.info("Testing password: secret123")
    sanitizing_logger.info("API key: abcd1234efgh5678")

    print("\n[+] Logging test complete - check logs/toolkit.log")
