# Project Structure Guide

Comprehensive guide to the Offensive Security Toolkit project structure, organization principles, and conventions.

**Last Updated**: 2025-10-17
**Version**: 0.3.0

---

## Table of Contents

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [Naming Conventions](#naming-conventions)
- [Module Organization](#module-organization)
- [Configuration](#configuration)
- [Testing Structure](#testing-structure)
- [Output and Logs](#output-and-logs)
- [Development Workflow](#development-workflow)

---

## Overview

The Offensive Security Toolkit follows a modular, category-based structure aligned with the MITRE ATT&CK framework. Each module represents a specific security testing category (reconnaissance, exploitation, post-exploitation, etc.).

### Design Principles

1. **Modularity**: Each security domain is a self-contained module
2. **MITRE ATT&CK Alignment**: Tools mapped to specific ATT&CK techniques
3. **Python Best Practices**: PEP 8 compliance with underscore naming
4. **Separation of Concerns**: Utilities, configs, and tools are separate
5. **Test Coverage**: Comprehensive unit and integration tests

---

## Directory Structure

```
offensive-toolkit/
│
├── reconnaissance/          # OSINT and information gathering [TA0043]
│   ├── __init__.py          # Module initialization
│   ├── dns_resolver.py      # DNS lookups [T1590.002]
│   ├── subdomain_enum.py    # Subdomain enumeration [T1590.001]
│   ├── whois_lookup.py      # WHOIS intelligence [T1590.001]
│   └── port_scanner.py      # Network service discovery [T1046]
│
├── web_security/            # Web application security [T1190]
│   ├── __init__.py
│   ├── sql_injection.py     # SQL injection scanner
│   ├── xss_scanner.py       # XSS vulnerability detection
│   └── directory_bruteforcer.py  # Web path discovery
│
├── cloud_security/          # Cloud security testing [TA0042, TA0007]
│   ├── __init__.py
│   ├── aws_scanner.py       # AWS misconfiguration scanner [T1580]
│   ├── azure_scanner.py     # Azure security scanner [T1580]
│   ├── gcp_scanner.py       # GCP security scanner [T1580]
│   └── cloud_cli.py         # Multi-cloud unified scanner
│
├── api_security/            # API security testing [T1190]
│   ├── __init__.py
│   ├── api_fuzzer.py        # OWASP API Top 10 2023 fuzzer
│   └── graphql_scanner.py   # GraphQL security scanner
│
├── post_exploitation/       # Post-access tools [Multiple Tactics]
│   ├── __init__.py
│   ├── persistence.py       # Persistence mechanisms [TA0003]
│   ├── privesc_windows.py   # Windows privilege escalation [TA0004]
│   ├── privesc_linux.py     # Linux privilege escalation [TA0004]
│   ├── privesc_scanner.py   # Unified privesc CLI
│   ├── credential_dump.py   # Credential harvesting [TA0006]
│   └── lateral_movement.py  # Lateral movement [TA0008]
│
├── exploitation/            # Exploit development [TA0002]
│   ├── __init__.py
│   └── reverse_shell.py     # Reverse shell generator [T1059]
│
├── reporting/               # Report generation & integration
│   ├── __init__.py
│   ├── report_generator.py  # Professional HTML/JSON reports
│   ├── defectdojo_client.py # DefectDojo API integration
│   └── unified_report.py    # All-in-one reporting CLI
│
├── scanning/                # Network scanning [TA0042]
│   └── __init__.py          # Placeholder module
│
├── evasion/                 # AV/EDR evasion [TA0005]
│   └── __init__.py          # Placeholder module
│
├── wireless/                # Wireless security testing
│   └── __init__.py          # Placeholder module
│
├── payload_development/     # Payload creation [TA0005]
│   └── __init__.py          # Placeholder module
│
├── social_engineering/      # Social engineering [TA0001]
│   └── __init__.py          # Placeholder module
│
├── utils/                   # Common utilities
│   ├── __init__.py
│   ├── logger.py            # Centralized logging
│   ├── config.py            # Configuration management
│   └── helpers.py           # Helper functions
│
├── config/                  # Configuration files
│   ├── README.md            # Configuration guide
│   ├── config.yaml.template # Main configuration template
│   └── authorized_targets.txt.template  # Target list template
│
├── tests/                   # Test suite
│   ├── __init__.py
│   ├── conftest.py          # Pytest configuration and fixtures
│   ├── README.md            # Testing guide
│   ├── fixtures/            # Test data and fixtures
│   ├── unit/                # Unit tests
│   │   ├── __init__.py
│   │   ├── test_config.py
│   │   ├── test_helpers.py
│   │   ├── test_logger.py
│   │   ├── test_port_scanner.py
│   │   ├── test_reverse_shell.py
│   │   └── test_directory_bruteforcer.py
│   └── integration/         # Integration tests
│       ├── __init__.py
│       ├── test_reconnaissance_workflow.py
│       └── test_web_security_workflow.py
│
├── docs/                    # Documentation
│   ├── ARCHITECTURE.md      # Architecture documentation
│   ├── MITRE-MAPPING.md     # MITRE ATT&CK mapping
│   ├── PROJECT-STRUCTURE.md # This file
│   ├── DEFECTDOJO-INTEGRATION.md  # DefectDojo guide
│   └── POST-EXPLOITATION-GUIDE.md  # Post-exploitation guide
│
├── .github/                 # GitHub Actions workflows
│   └── workflows/
│       └── ci.yml           # CI/CD pipeline
│
├── logs/                    # Log files (gitignored)
├── output/                  # Tool output (gitignored)
├── venv/                    # Virtual environment (gitignored)
│
├── .gitignore               # Git ignore rules
├── .pre-commit-config.yaml  # Pre-commit hooks
├── __init__.py              # Root package initialization
├── README.md                # Main project documentation
├── SECURITY.md              # Security policy and ethical guidelines
├── CONTRIBUTING.md          # Contribution guidelines
├── CHANGELOG.md             # Version history
├── requirements.txt         # Python dependencies
├── pyproject.toml           # Build configuration
├── setup.sh                 # Linux/Mac setup script
└── setup.ps1                # Windows setup script
```

---

## Naming Conventions

### Python Modules and Packages

**CRITICAL**: Use underscores, NEVER hyphens in Python module names.

#### Why Underscores?

Python identifiers cannot contain hyphens. This code will fail:

```python
# INVALID - SyntaxError!
from web-security import sql_injection
```

This code works:

```python
# VALID
from web_security import sql_injection
```

#### Naming Rules

| Component | Convention | Example |
|-----------|------------|---------|
| **Modules/Packages** | `lowercase_with_underscores` | `web_security/`, `post_exploitation/` |
| **Python Files** | `lowercase_with_underscores.py` | `port_scanner.py`, `dns_resolver.py` |
| **Classes** | `PascalCase` | `PortScanner`, `DNSResolver` |
| **Functions** | `lowercase_with_underscores` | `scan_port()`, `resolve_dns()` |
| **Constants** | `UPPERCASE_WITH_UNDERSCORES` | `MAX_THREADS`, `DEFAULT_TIMEOUT` |
| **Private Members** | `_leading_underscore` | `_validate_input()`, `_rate_limit` |

#### Repository Name Exception

The repository name `offensive-toolkit` uses hyphens, which is acceptable because:
- It's not a Python identifier
- It's only used for git clone URLs
- Internal Python code uses underscores

---

## Module Organization

### Module Structure Template

Each security module should follow this structure:

```
module_name/
├── __init__.py              # Module initialization and exports
├── tool1.py                 # Individual tool
├── tool2.py                 # Individual tool
├── tool3_cli.py             # Unified CLI for multiple tools
└── README.md                # Module-specific documentation (optional)
```

### `__init__.py` Template

```python
"""
Module Name - Brief Description

This module provides tools for [category] including:
- Tool 1 description
- Tool 2 description

MITRE ATT&CK Mapping:
- TA0043: Reconnaissance
- T1590.001: Gather Victim Network Information

All tools require explicit authorization before use.
"""

__version__ = "0.3.0"
__author__ = "Offensive Toolkit Contributors"

# Module exports
__all__ = [
    "tool1",
    "tool2",
    "tool3_cli",
]
```

### Tool File Template

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the complete tool template.

---

## Configuration

### Configuration Files

Configuration files live in `config/` directory:

```
config/
├── README.md                        # Configuration guide
├── config.yaml.template             # Main config template
├── config.yaml                      # Actual config (gitignored)
├── authorized_targets.txt.template  # Targets template
└── authorized_targets.txt           # Actual targets (gitignored)
```

### Configuration Loading

```python
from utils.config import load_config

# Load default config
config = load_config()

# Load custom config
config = load_config("path/to/config.yaml")

# Access nested config
rate_limit = config.get("rate_limit", {}).get("requests_per_second", 10)
```

### Environment Variables

Override configuration with `OSTK_` prefixed environment variables:

```bash
export OSTK_RATE_LIMIT__REQUESTS_PER_SECOND=5
export OSTK_LOGGING__LEVEL=DEBUG
export OSTK_AUTHORIZATION__REQUIRE_CONFIRMATION=false
```

Format: `OSTK_<SECTION>__<KEY>=<VALUE>`

---

## Testing Structure

### Test Organization

```
tests/
├── conftest.py              # Pytest fixtures (shared across all tests)
├── README.md                # Testing guide
├── fixtures/                # Test data
│   ├── sample_targets.txt
│   └── test_wordlist.txt
├── unit/                    # Unit tests (fast, isolated)
│   ├── test_config.py       # Test utils/config.py
│   ├── test_helpers.py      # Test utils/helpers.py
│   ├── test_logger.py       # Test utils/logger.py
│   └── test_*.py            # One file per module
└── integration/             # Integration tests (slower, end-to-end)
    ├── test_reconnaissance_workflow.py
    └── test_web_security_workflow.py
```

### Test Naming Convention

```python
# File: tests/unit/test_port_scanner.py
class TestPortScanner:
    def test_initialization(self):
        """Test PortScanner class initialization."""
        pass

    def test_scan_port_open(self):
        """Test scanning an open port."""
        pass

    def test_scan_port_closed(self):
        """Test scanning a closed port."""
        pass

    def test_invalid_target(self):
        """Test handling of invalid target."""
        pass
```

### Running Tests

```bash
# All tests
pytest

# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# With coverage
pytest --cov=. --cov-report=html

# Specific test
pytest tests/unit/test_port_scanner.py::TestPortScanner::test_scan_port_open
```

---

## Output and Logs

### Output Directory Structure

```
output/
├── portscan_192.168.1.10_20251017_143022.json
├── webscan_example.com_20251017_144512.json
└── cloud_scan_aws_20251017_150045.json
```

### Log Directory Structure

```
logs/
└── toolkit.log              # Main application log
```

### Output File Naming

Format: `{tool}_{target}_{timestamp}.{format}`

Examples:
- `portscan_192.168.1.10_20251017_143022.json`
- `sqlinjection_example.com_20251017_150030.html`
- `cloud_scan_aws_20251017_160015.json`

---

## Development Workflow

### Adding a New Tool

1. **Create the tool file** in the appropriate module directory
2. **Follow the tool template** from CONTRIBUTING.md
3. **Add to `__init__.py`** exports
4. **Create unit tests** in `tests/unit/test_newtool.py`
5. **Update module README** (if exists)
6. **Update MITRE-MAPPING.md** with technique IDs
7. **Update CHANGELOG.md** with changes
8. **Test thoroughly** before committing

### Adding a New Module

1. **Create module directory** (use underscores!)
   ```bash
   mkdir new_module
   ```

2. **Create `__init__.py`** with module docstring

3. **Add to root `__init__.py`** (if needed)

4. **Create `tests/unit/test_new_module*.py`**

5. **Update README.md** with module description

6. **Update docs/MITRE-MAPPING.md**

---

## Best Practices

### DO ✓

- Use underscores in all Python module/package names
- Follow PEP 8 naming conventions
- Include authorization checks in all tools
- Write comprehensive docstrings
- Add unit tests for all new code
- Keep modules focused and cohesive
- Use type hints for function signatures
- Log important events and errors

### DON'T ✗

- Use hyphens in Python module names (will break imports!)
- Commit virtual environment files (venv/, Lib/, Scripts/)
- Commit sensitive data (credentials, API keys, target lists)
- Skip authorization checks
- Write tools without rate limiting
- Leave placeholder TODOs in production code
- Mix tabs and spaces for indentation

---

## Common Issues and Solutions

### Import Errors

**Problem**: `ModuleNotFoundError: No module named 'web-security'`

**Solution**: Module uses hyphens. Rename to `web_security`:
```bash
mv web-security web_security
# Update imports: from web_security import ...
```

### Virtual Environment Pollution

**Problem**: Lib/ and Scripts/ directories in repository

**Solution**: These are virtual environment artifacts. Remove and ensure .gitignore excludes them:
```bash
rm -rf Lib/ Scripts/
# Check .gitignore includes venv/, env/, Lib/, Scripts/
```

### Missing `__init__.py`

**Problem**: `ImportError: cannot import name 'module'`

**Solution**: Every package directory needs `__init__.py`:
```bash
touch module_name/__init__.py
```

---

## References

- [PEP 8 – Style Guide for Python Code](https://peps.python.org/pep-0008/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Python Packaging User Guide](https://packaging.python.org/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)

---

## Changelog

### 2025-10-17 - v1.0
- Initial PROJECT-STRUCTURE.md creation
- Documented naming conventions (underscores vs hyphens)
- Added module organization guidelines
- Included development workflow best practices

---

**For questions or clarifications, see [CONTRIBUTING.md](../CONTRIBUTING.md) or open an issue.**
