# Contributing to Offensive Security Toolkit

Thank you for your interest in contributing to the Offensive Security Toolkit! This document provides guidelines and instructions for contributing to this project.

## [!] Code of Conduct

### Ethical Guidelines

By contributing to this project, you agree to:

- **ONLY develop tools for authorized security testing and defensive purposes**
- **NEVER create or improve code intended for malicious use**
- **NEVER contribute exploits or techniques for unauthorized access**
- **ALWAYS prioritize responsible disclosure and ethical security research**
- **COMPLY with all applicable laws and regulations**

Violations of these ethical guidelines will result in immediate removal of contributions and potential legal action.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contribution Workflow](#contribution-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Documentation Standards](#documentation-standards)
- [Pull Request Process](#pull-request-process)
- [Security Considerations](#security-considerations)
- [License](#license)

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv)
- Familiarity with security testing concepts
- Understanding of MITRE ATT&CK framework (preferred)

### Areas for Contribution

We welcome contributions in these areas:

1. **New Security Tools**: Implement new modules aligned with MITRE ATT&CK
2. **Bug Fixes**: Fix issues in existing tools
3. **Documentation**: Improve guides, tutorials, and API docs
4. **Testing**: Add unit tests, integration tests, or security tests
5. **Performance**: Optimize existing tools for speed or resource usage
6. **CI/CD**: Improve automation and build processes
7. **Examples**: Add practical usage examples and tutorials

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub first
git clone https://github.com/yourusername/offensive-toolkit.git
cd offensive-toolkit

# Add upstream remote
git remote add upstream https://github.com/original/offensive-toolkit.git
```

### 2. Create Virtual Environment

**Linux/Mac**:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

**Windows**:
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 3. Install Development Tools

```bash
pip install black flake8 mypy pytest pytest-cov pre-commit
pre-commit install
```

### 4. Verify Setup

```bash
# Run tests
pytest tests/

# Check code style
flake8 .

# Check type hints
mypy .
```

## Contribution Workflow

### 1. Create a Feature Branch

```bash
# Sync with upstream
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name
```

**Branch Naming Conventions**:
- `feature/` - New features or tools
- `bugfix/` - Bug fixes
- `docs/` - Documentation updates
- `test/` - Testing improvements
- `refactor/` - Code refactoring

### 2. Make Your Changes

Follow the coding standards and ensure all tests pass.

### 3. Commit Your Changes

```bash
git add .
git commit -m "feat: Add port scanner with rate limiting"
```

**Commit Message Format**:
```
<type>: <description>

[optional body]

[optional footer]
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

### 4. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub.

## Coding Standards

### Python Style Guide

We follow PEP 8 with some modifications:

```python
# Maximum line length: 100 characters (not 79)
# Use double quotes for strings (not single quotes)
# Use type hints for all function signatures
```

### Code Formatting

Use `black` for automatic formatting:

```bash
black .
```

### Linting

Use `flake8` for linting:

```bash
flake8 . --max-line-length=100
```

### Type Checking

Use `mypy` for static type checking:

```bash
mypy . --ignore-missing-imports
```

### Tool Template Structure

All tools should follow this template:

```python
#!/usr/bin/env python3
"""
Tool Name - Brief Description

This tool performs [description] for authorized security testing.

[!] AUTHORIZATION REQUIRED: Only use on systems you have explicit permission to test.

Usage:
    python tool_name.py --target <target> [options]

Example:
    python tool_name.py --target 192.168.1.0/24 --rate-limit 10

Author: Your Name
Date: YYYY-MM-DD
MITRE ATT&CK: T1234 (Technique Name)
"""

import argparse
import sys
from typing import Optional, Dict, Any

from utils.logger import get_logger
from utils.config import load_config
from utils.helpers import validate_target, check_authorization, rate_limit

logger = get_logger(__name__)


class ToolName:
    """
    ToolName class for [brief description].

    Attributes:
        config (Dict[str, Any]): Configuration dictionary
        target (str): Target identifier
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the tool.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or load_config()
        logger.info(f"Initialized {self.__class__.__name__}")

    def run(self, target: str) -> bool:
        """
        Execute the main tool functionality.

        Args:
            target: Target to test (IP, domain, URL, etc.)

        Returns:
            bool: True if successful, False otherwise
        """
        # Authorization check
        if not check_authorization(target, self.config):
            logger.error(f"Target {target} not authorized for testing")
            return False

        # Validate target format
        if not validate_target(target):
            logger.error(f"Invalid target format: {target}")
            return False

        logger.info(f"Running {self.__class__.__name__} against {target}")

        try:
            # Tool implementation here
            result = self._execute(target)
            self._save_results(result)
            return True

        except Exception as e:
            logger.error(f"Error during execution: {str(e)}", exc_info=True)
            return False

    def _execute(self, target: str) -> Dict[str, Any]:
        """
        Internal execution logic.

        Args:
            target: Target identifier

        Returns:
            Dict containing results
        """
        # Implementation
        pass

    def _save_results(self, results: Dict[str, Any]) -> None:
        """
        Save results to output directory.

        Args:
            results: Results dictionary to save
        """
        # Save logic
        pass


def main() -> int:
    """
    Main entry point for command-line usage.

    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    parser = argparse.ArgumentParser(
        description="Tool Name - Brief Description",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target to test (IP, domain, URL, etc.)"
    )

    parser.add_argument(
        "--config",
        help="Path to configuration file"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config) if args.config else None

    # Create and run tool
    tool = ToolName(config)
    success = tool.run(args.target)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
```

### Documentation Standards

All code must include:

1. **Module docstrings**: Describe the module purpose and usage
2. **Class docstrings**: Describe the class and its attributes
3. **Function docstrings**: Use Google-style docstrings
4. **Inline comments**: For complex logic
5. **Type hints**: For all function signatures

**Google-style Docstring Example**:

```python
def function_name(param1: str, param2: int) -> bool:
    """
    Brief description of function.

    Longer description if needed, explaining what the function does,
    any important details, algorithms used, etc.

    Args:
        param1: Description of first parameter
        param2: Description of second parameter

    Returns:
        Description of return value

    Raises:
        ValueError: When param2 is negative
        ConnectionError: When network connection fails

    Example:
        >>> function_name("test", 10)
        True
    """
    pass
```

## Testing Requirements

### Unit Tests

All new code must include unit tests:

```python
# tests/test_tool_name.py
import pytest
from reconnaissance.tool_name import ToolName


class TestToolName:
    """Test suite for ToolName."""

    def test_initialization(self):
        """Test tool initialization."""
        tool = ToolName()
        assert tool is not None

    def test_valid_target(self):
        """Test with valid target."""
        tool = ToolName()
        result = tool.run("192.168.1.1")
        assert result is True

    def test_invalid_target(self):
        """Test with invalid target."""
        tool = ToolName()
        result = tool.run("invalid")
        assert result is False
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_tool_name.py

# Run specific test
pytest tests/test_tool_name.py::TestToolName::test_valid_target
```

### Test Coverage Requirements

- **Minimum coverage**: 80% for new code
- **Critical functions**: 100% coverage required
- **Integration tests**: Required for complex modules

## Documentation Standards

### README Files

Each module should have a README.md:

```markdown
# Module Name

Brief description of the module.

## Tools

- **tool1.py**: Description of tool 1
- **tool2.py**: Description of tool 2

## Usage

### Tool 1

\`\`\`bash
python tool1.py --target <target>
\`\`\`

## MITRE ATT&CK Mapping

- T1234: Technique Name

## Authorization

[!] All tools in this module require explicit authorization before use.
```

### API Documentation

Generate API docs with:

```bash
# Install sphinx
pip install sphinx sphinx-rtd-theme

# Generate docs
cd docs/
sphinx-apidoc -o . ..
make html
```

## Pull Request Process

### Before Submitting

1. **Run all tests**: `pytest`
2. **Check code style**: `black . && flake8 .`
3. **Update documentation**: Add/update relevant docs
4. **Update CHANGELOG.md**: Add your changes
5. **Rebase on main**: `git rebase upstream/main`

### Pull Request Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Checklist

- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] All tests pass
- [ ] CHANGELOG.md updated
- [ ] MITRE mapping updated (if applicable)

## Testing

Describe how you tested your changes.

## MITRE ATT&CK Mapping

If adding new tools, provide MITRE ATT&CK technique IDs.

## Authorization Statement

I confirm that this contribution is intended for defensive security purposes only and will not enable unauthorized access or malicious activities.

## Screenshots (if applicable)

Add screenshots for UI changes or tool output.
```

### Review Process

1. **Automated checks**: CI/CD pipeline runs tests
2. **Code review**: At least one maintainer reviews
3. **Security review**: For sensitive changes
4. **Documentation review**: Ensure docs are complete
5. **Approval**: Maintainer approves and merges

## Security Considerations

### Sensitive Data

- **NEVER commit credentials, API keys, or secrets**
- Use `.env` files (gitignored) for configuration
- Use environment variables for sensitive data
- Sanitize logs to remove sensitive information

### Authorization Checks

All tools must:

1. Check `config/authorized_targets.txt` before running
2. Prompt for confirmation unless disabled
3. Log all authorization checks
4. Fail safely if authorization check fails

### Rate Limiting

All network tools must:

1. Implement rate limiting
2. Respect `robots.txt`
3. Honor rate limit headers
4. Allow configurable request rates

### Responsible Disclosure

If you discover vulnerabilities:

1. **DO NOT** exploit them maliciously
2. Report privately to maintainers
3. Allow 90 days for patching
4. Follow coordinated disclosure

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Open an issue for questions
- Join our Discord/Slack (if available)
- Email maintainers for sensitive topics

---

**Thank you for contributing to defensive security!**

Last Updated: 2025-10-15
