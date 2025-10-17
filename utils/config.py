#!/usr/bin/env python3
"""
Configuration Management Module

Handles loading, saving, and managing configuration for the toolkit.
Supports YAML, JSON, and environment variable configuration.

Author: David Dashti
Date: 2025-10-15
"""

import json
import os
from pathlib import Path
from typing import Any

import yaml

from utils.logger import get_logger

logger = get_logger(__name__)


# Default configuration paths
DEFAULT_CONFIG_DIR = "config"
DEFAULT_CONFIG_FILE = "config.yaml"
DEFAULT_TARGETS_FILE = "authorized_targets.txt"


# Default configuration values
DEFAULT_CONFIG = {
    "logging": {
        "level": "INFO",
        "file": "logs/toolkit.log",
        "format": "[%(asctime)s] [%(levelname)s] %(message)s",
    },
    "rate_limit": {
        "enabled": True,
        "requests_per_second": 10,
    },
    "timeouts": {
        "connection": 10,
        "read": 30,
    },
    "output": {
        "directory": "output",
        "format": "json",
    },
    "authorization": {
        "require_confirmation": True,
        "scope_file": f"{DEFAULT_CONFIG_DIR}/{DEFAULT_TARGETS_FILE}",
    },
    "user_agent": "Offensive-Security-Toolkit/0.1.0 (Authorized Testing)",
}


def load_config(config_path: str | None = None) -> dict[str, Any]:
    """
    Load configuration from file with fallback to defaults.

    Supports YAML and JSON formats. Environment variables override file config.

    Args:
        config_path: Path to configuration file (default: config/config.yaml)

    Returns:
        Configuration dictionary

    Example:
        >>> config = load_config()
        >>> print(config['rate_limit']['requests_per_second'])
        10
    """
    # Start with default configuration
    config = DEFAULT_CONFIG.copy()

    # Determine config file path
    if config_path is None:
        config_dir = Path(DEFAULT_CONFIG_DIR)
        config_dir.mkdir(exist_ok=True)
        config_path = str(config_dir / DEFAULT_CONFIG_FILE)

    # Load from file if it exists
    config_file = Path(config_path)
    if config_file.exists():
        try:
            with open(config_file) as f:
                if config_path.endswith(".yaml") or config_path.endswith(".yml"):
                    file_config = yaml.safe_load(f)
                elif config_path.endswith(".json"):
                    file_config = json.load(f)
                else:
                    logger.warning(f"Unknown config format: {config_path}")
                    file_config = {}

                # Deep merge with defaults
                config = deep_merge(config, file_config)
                logger.info(f"Configuration loaded from {config_path}")

        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {e}")
            logger.info("Using default configuration")

    else:
        logger.info(f"Config file not found: {config_path}")
        logger.info("Using default configuration")

    # Override with environment variables
    config = apply_env_overrides(config)

    return config


def save_config(config: dict[str, Any], config_path: str | None = None) -> bool:
    """
    Save configuration to file.

    Args:
        config: Configuration dictionary to save
        config_path: Path to save configuration (default: config/config.yaml)

    Returns:
        True if successful, False otherwise

    Example:
        >>> config = load_config()
        >>> config['rate_limit']['requests_per_second'] = 20
        >>> save_config(config)
        True
    """
    if config_path is None:
        config_dir = Path(DEFAULT_CONFIG_DIR)
        config_dir.mkdir(exist_ok=True)
        config_path = str(config_dir / DEFAULT_CONFIG_FILE)

    try:
        with open(config_path, "w") as f:
            if config_path.endswith(".yaml") or config_path.endswith(".yml"):
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            elif config_path.endswith(".json"):
                json.dump(config, f, indent=2)
            else:
                logger.error(f"Unknown config format: {config_path}")
                return False

        logger.info(f"Configuration saved to {config_path}")
        return True

    except Exception as e:
        logger.error(f"Error saving config to {config_path}: {e}")
        return False


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """
    Deep merge two dictionaries, with override taking precedence.

    Args:
        base: Base dictionary
        override: Dictionary with overriding values

    Returns:
        Merged dictionary

    Example:
        >>> base = {'a': 1, 'b': {'c': 2}}
        >>> override = {'b': {'d': 3}}
        >>> deep_merge(base, override)
        {'a': 1, 'b': {'c': 2, 'd': 3}}
    """
    result = base.copy()

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value

    return result


def apply_env_overrides(config: dict[str, Any]) -> dict[str, Any]:
    """
    Apply environment variable overrides to configuration.

    Environment variables should be prefixed with OSTK_ (Offensive Security Toolkit)
    and use double underscores for nesting: OSTK_RATE_LIMIT__ENABLED=false

    Args:
        config: Base configuration dictionary

    Returns:
        Configuration with environment variable overrides

    Example:
        >>> os.environ['OSTK_RATE_LIMIT__ENABLED'] = 'false'
        >>> config = apply_env_overrides({'rate_limit': {'enabled': True}})
        >>> config['rate_limit']['enabled']
        False
    """
    prefix = "OSTK_"

    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue

        # Remove prefix and split on double underscore
        config_path = key[len(prefix) :].lower().split("__")

        # Navigate to the nested config location
        current = config
        for path_part in config_path[:-1]:
            if path_part not in current:
                current[path_part] = {}
            current = current[path_part]

        # Set the value, attempting type conversion
        final_key = config_path[-1]
        current[final_key] = parse_env_value(value)

        logger.debug(f"Environment override: {key} = {value}")

    return config


def parse_env_value(value: str) -> Any:
    """
    Parse environment variable value to appropriate Python type.

    Args:
        value: String value from environment variable

    Returns:
        Parsed value (bool, int, float, or str)

    Example:
        >>> parse_env_value("true")
        True
        >>> parse_env_value("42")
        42
        >>> parse_env_value("3.14")
        3.14
    """
    # Boolean
    if value.lower() in ("true", "yes", "1", "on"):
        return True
    if value.lower() in ("false", "no", "0", "off"):
        return False

    # Integer
    try:
        return int(value)
    except ValueError:
        pass

    # Float
    try:
        return float(value)
    except ValueError:
        pass

    # String (default)
    return value


def get_config_value(config: dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Get a configuration value using dot notation path.

    Args:
        config: Configuration dictionary
        path: Dot-separated path (e.g., "rate_limit.enabled")
        default: Default value if path not found

    Returns:
        Configuration value or default

    Example:
        >>> config = load_config()
        >>> get_config_value(config, "rate_limit.enabled", False)
        True
    """
    keys = path.split(".")
    current = config

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default

    return current


def set_config_value(config: dict[str, Any], path: str, value: Any) -> None:
    """
    Set a configuration value using dot notation path.

    Args:
        config: Configuration dictionary
        path: Dot-separated path (e.g., "rate_limit.enabled")
        value: Value to set

    Example:
        >>> config = load_config()
        >>> set_config_value(config, "rate_limit.enabled", False)
    """
    keys = path.split(".")
    current = config

    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]

    current[keys[-1]] = value


if __name__ == "__main__":
    # Test configuration functionality
    print("[*] Testing configuration management...")

    # Load default config
    config = load_config()
    print("\n[+] Loaded configuration:")
    print(yaml.dump(config, default_flow_style=False))

    # Test getting values
    rate_limit = get_config_value(config, "rate_limit.requests_per_second")
    print(f"\n[+] Rate limit: {rate_limit} requests/second")

    # Test setting values
    set_config_value(config, "rate_limit.requests_per_second", 20)
    print(f"[+] Updated rate limit: {get_config_value(config, 'rate_limit.requests_per_second')}")

    print("\n[+] Configuration test complete")
