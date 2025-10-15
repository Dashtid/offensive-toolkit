"""
Unit tests for utils/config.py module.
"""

import pytest
import yaml
import json
import os
from pathlib import Path
from utils.config import (
    load_config,
    save_config,
    deep_merge,
    apply_env_overrides,
    parse_env_value,
    get_config_value,
    set_config_value,
    DEFAULT_CONFIG
)


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_default_config(self):
        """Test loading default configuration when no file exists."""
        config = load_config("nonexistent_config.yaml")

        assert config is not None
        assert "logging" in config
        assert "rate_limit" in config
        assert "authorization" in config

    def test_load_yaml_config(self, temp_dir):
        """Test loading YAML configuration file."""
        config_file = temp_dir / "test.yaml"
        test_config = {
            "rate_limit": {"requests_per_second": 20},
            "custom_key": "custom_value"
        }

        with open(config_file, "w") as f:
            yaml.dump(test_config, f)

        config = load_config(str(config_file))

        assert config["rate_limit"]["requests_per_second"] == 20
        assert config["custom_key"] == "custom_value"

    def test_load_json_config(self, temp_dir):
        """Test loading JSON configuration file."""
        config_file = temp_dir / "test.json"
        test_config = {
            "timeouts": {"connection": 15},
            "test_key": "test_value"
        }

        with open(config_file, "w") as f:
            json.dump(test_config, f)

        config = load_config(str(config_file))

        assert config["timeouts"]["connection"] == 15
        assert config["test_key"] == "test_value"

    def test_load_invalid_file(self, temp_dir):
        """Test loading invalid configuration file falls back to defaults."""
        config_file = temp_dir / "invalid.yaml"
        config_file.write_text("invalid: yaml: content:")

        config = load_config(str(config_file))

        # Should fallback to defaults
        assert "logging" in config
        assert "rate_limit" in config


class TestSaveConfig:
    """Tests for save_config function."""

    def test_save_yaml_config(self, temp_dir):
        """Test saving configuration to YAML file."""
        config_file = temp_dir / "save_test.yaml"
        test_config = {
            "test": "value",
            "number": 42
        }

        result = save_config(test_config, str(config_file))

        assert result is True
        assert config_file.exists()

        # Verify content
        with open(config_file, "r") as f:
            loaded = yaml.safe_load(f)

        assert loaded["test"] == "value"
        assert loaded["number"] == 42

    def test_save_json_config(self, temp_dir):
        """Test saving configuration to JSON file."""
        config_file = temp_dir / "save_test.json"
        test_config = {
            "test": "value",
            "nested": {"key": "value"}
        }

        result = save_config(test_config, str(config_file))

        assert result is True
        assert config_file.exists()

        # Verify content
        with open(config_file, "r") as f:
            loaded = json.load(f)

        assert loaded["test"] == "value"
        assert loaded["nested"]["key"] == "value"


class TestDeepMerge:
    """Tests for deep_merge function."""

    def test_merge_simple_dicts(self):
        """Test merging simple dictionaries."""
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}

        result = deep_merge(base, override)

        assert result["a"] == 1
        assert result["b"] == 3  # Override wins
        assert result["c"] == 4

    def test_merge_nested_dicts(self):
        """Test merging nested dictionaries."""
        base = {
            "level1": {
                "level2": {
                    "key1": "value1",
                    "key2": "value2"
                }
            }
        }
        override = {
            "level1": {
                "level2": {
                    "key2": "new_value",
                    "key3": "value3"
                }
            }
        }

        result = deep_merge(base, override)

        assert result["level1"]["level2"]["key1"] == "value1"
        assert result["level1"]["level2"]["key2"] == "new_value"
        assert result["level1"]["level2"]["key3"] == "value3"

    def test_merge_replaces_non_dict(self):
        """Test merging replaces non-dict values."""
        base = {"key": "string_value"}
        override = {"key": {"nested": "dict"}}

        result = deep_merge(base, override)

        assert isinstance(result["key"], dict)
        assert result["key"]["nested"] == "dict"


class TestParseEnvValue:
    """Tests for parse_env_value function."""

    def test_parse_boolean_true(self):
        """Test parsing boolean true values."""
        assert parse_env_value("true") is True
        assert parse_env_value("True") is True
        assert parse_env_value("yes") is True
        assert parse_env_value("1") is True
        assert parse_env_value("on") is True

    def test_parse_boolean_false(self):
        """Test parsing boolean false values."""
        assert parse_env_value("false") is False
        assert parse_env_value("False") is False
        assert parse_env_value("no") is False
        assert parse_env_value("0") is False
        assert parse_env_value("off") is False

    def test_parse_integer(self):
        """Test parsing integer values."""
        assert parse_env_value("42") == 42
        assert parse_env_value("-10") == -10
        assert parse_env_value("0") is False  # 0 is boolean false

    def test_parse_float(self):
        """Test parsing float values."""
        assert parse_env_value("3.14") == 3.14
        assert parse_env_value("-2.5") == -2.5

    def test_parse_string(self):
        """Test parsing string values."""
        assert parse_env_value("hello") == "hello"
        assert parse_env_value("test value") == "test value"


class TestApplyEnvOverrides:
    """Tests for apply_env_overrides function."""

    def test_env_override_single_level(self, monkeypatch):
        """Test environment variable override at single level."""
        monkeypatch.setenv("OSTK_TEST_KEY", "test_value")

        config = {"existing": "value"}
        result = apply_env_overrides(config)

        assert result["test_key"] == "test_value"

    def test_env_override_nested(self, monkeypatch):
        """Test environment variable override with nested keys."""
        monkeypatch.setenv("OSTK_LEVEL1__LEVEL2__KEY", "nested_value")

        config = {}
        result = apply_env_overrides(config)

        assert result["level1"]["level2"]["key"] == "nested_value"

    def test_env_override_boolean(self, monkeypatch):
        """Test environment variable boolean conversion."""
        monkeypatch.setenv("OSTK_ENABLED", "true")

        config = {}
        result = apply_env_overrides(config)

        assert result["enabled"] is True

    def test_env_override_number(self, monkeypatch):
        """Test environment variable number conversion."""
        monkeypatch.setenv("OSTK_PORT", "8080")

        config = {}
        result = apply_env_overrides(config)

        assert result["port"] == 8080

    def test_env_no_ostk_prefix_ignored(self, monkeypatch):
        """Test environment variables without OSTK_ prefix are ignored."""
        monkeypatch.setenv("OTHER_VAR", "value")

        config = {"existing": "value"}
        result = apply_env_overrides(config)

        assert "other_var" not in result


class TestGetConfigValue:
    """Tests for get_config_value function."""

    def test_get_simple_value(self):
        """Test getting simple configuration value."""
        config = {"key": "value"}
        result = get_config_value(config, "key")

        assert result == "value"

    def test_get_nested_value(self):
        """Test getting nested configuration value."""
        config = {
            "level1": {
                "level2": {
                    "key": "value"
                }
            }
        }
        result = get_config_value(config, "level1.level2.key")

        assert result == "value"

    def test_get_missing_value_default(self):
        """Test getting missing value returns default."""
        config = {"key": "value"}
        result = get_config_value(config, "missing", default="default")

        assert result == "default"

    def test_get_missing_nested_value_default(self):
        """Test getting missing nested value returns default."""
        config = {"level1": {}}
        result = get_config_value(config, "level1.level2.key", default=None)

        assert result is None


class TestSetConfigValue:
    """Tests for set_config_value function."""

    def test_set_simple_value(self):
        """Test setting simple configuration value."""
        config = {}
        set_config_value(config, "key", "value")

        assert config["key"] == "value"

    def test_set_nested_value(self):
        """Test setting nested configuration value."""
        config = {}
        set_config_value(config, "level1.level2.key", "value")

        assert config["level1"]["level2"]["key"] == "value"

    def test_set_overwrites_existing(self):
        """Test setting value overwrites existing."""
        config = {"key": "old_value"}
        set_config_value(config, "key", "new_value")

        assert config["key"] == "new_value"

    def test_set_creates_intermediate_dicts(self):
        """Test setting value creates intermediate dictionaries."""
        config = {}
        set_config_value(config, "a.b.c.d", "value")

        assert isinstance(config["a"], dict)
        assert isinstance(config["a"]["b"], dict)
        assert isinstance(config["a"]["b"]["c"], dict)
        assert config["a"]["b"]["c"]["d"] == "value"


class TestConfigIntegration:
    """Integration tests for configuration functionality."""

    def test_load_save_roundtrip(self, temp_dir):
        """Test loading and saving configuration maintains data."""
        config_file = temp_dir / "roundtrip.yaml"

        original_config = {
            "test": "value",
            "nested": {
                "key": "value",
                "number": 42
            }
        }

        # Save
        save_config(original_config, str(config_file))

        # Load
        loaded_config = load_config(str(config_file))

        assert loaded_config["test"] == original_config["test"]
        assert loaded_config["nested"]["key"] == original_config["nested"]["key"]
        assert loaded_config["nested"]["number"] == original_config["nested"]["number"]

    def test_env_override_persists(self, monkeypatch):
        """Test environment overrides persist in loaded config."""
        monkeypatch.setenv("OSTK_RATE_LIMIT__REQUESTS_PER_SECOND", "50")

        config = load_config("nonexistent.yaml")

        assert config["rate_limit"]["requests_per_second"] == 50
