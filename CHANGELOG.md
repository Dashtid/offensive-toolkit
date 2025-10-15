# Changelog

All notable changes to the Offensive Security Toolkit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Comprehensive Testing Infrastructure**:
  - Full pytest framework with 70% coverage minimum
  - 140+ unit tests for utils modules (logger, config, helpers)
  - Unit tests for port scanner, directory bruteforcer, reverse shell
  - Integration tests for reconnaissance workflow
  - Integration tests for web security workflow
  - GitHub Actions CI/CD pipeline (multi-OS, multi-Python version)
  - Pre-commit hooks with black, flake8, bandit, mypy
  - 30+ development dependencies in requirements-dev.txt
  - Comprehensive testing documentation (docs/TESTING-GUIDE.md)

- **Reconnaissance Tools** (MITRE TA0043):
  - [+] DNS Resolver (T1590.002) - Multi-resolver DNS lookups with all record types
  - [+] Subdomain Enumerator (T1590.001) - DNS brute-force + certificate transparency
  - [+] WHOIS Lookup (T1590.001) - Domain intelligence gathering with parsing
  - [+] Port Scanner (T1046) - Multi-threaded scanning with rate limiting (existing)

- **Web Security Tools**:
  - [+] SQL Injection Scanner (T1190) - Multiple injection types (union, boolean, time-based, error-based)
  - [+] XSS Scanner (T1189) - Reflected, stored, and DOM-based XSS detection
  - [+] Directory Bruteforcer (T1083) - Web path discovery (existing)

- **Testing Features**:
  - Shared pytest fixtures for mocking (socket, HTTP responses)
  - Parametrized tests for comprehensive coverage
  - Test data factories and sample results
  - Code coverage reporting (HTML + terminal)
  - Security scanning with Bandit in CI/CD
  - Dependency safety checks in pipeline

### Changed
- Enhanced utils modules with comprehensive test coverage
- Improved rate limiting implementation with token bucket algorithm
- Updated configuration system with better environment variable support

### Planned
- OSINT collection tools
- Social engineering templates
- Credential testing tools
- Advanced exploitation modules
- Post-exploitation persistence tools

## [0.1.0] - 2025-10-15

### Added
- Initial project structure with modular architecture
- Comprehensive directory organization:
  - `reconnaissance/` - Information gathering tools
  - `scanning/` - Network and vulnerability scanning
  - `exploitation/` - Exploit development and testing
  - `post-exploitation/` - Post-access tools
  - `social-engineering/` - Phishing and social tests
  - `wireless/` - Wireless security testing
  - `web-security/` - Web application security
  - `payload-development/` - Payload creation
  - `evasion/` - AV/EDR evasion techniques
  - `reporting/` - Report generation
  - `utils/` - Common utilities and helpers

### Documentation
- [+] README.md with project overview and usage guidelines
- [+] SECURITY.md with ethical use policy and legal disclaimers
- [+] CONTRIBUTING.md with contribution guidelines and coding standards
- [+] ARCHITECTURE.md with detailed architecture documentation
- [+] MITRE-MAPPING.md with MITRE ATT&CK framework alignment
- [+] .gitignore with comprehensive security-focused exclusions

### Infrastructure
- [+] Python package structure with `__init__.py` files
- [+] `requirements.txt` with essential security testing libraries:
  - requests, beautifulsoup4, lxml for web testing
  - scapy, pyshark for network analysis
  - impacket, paramiko for protocol testing
  - cryptography, pycryptodome for crypto operations
  - selenium, playwright for browser automation
  - loguru for logging
  - pytest for testing
- [+] `setup.sh` - Linux/Mac installation script
- [+] `setup.ps1` - Windows PowerShell installation script
- [+] Configuration system with YAML support
- [+] Logging infrastructure with file and console output
- [+] Authorization checking system

### Security Features
- [+] Authorization validation before tool execution
- [+] Rate limiting to prevent abuse
- [+] Comprehensive `.gitignore` to prevent credential leaks
- [+] Audit logging for all operations
- [+] Ethical use warnings in all modules

### MITRE ATT&CK Coverage
- [+] Mapped ~120 techniques across 13 tactics
- [+] Reconnaissance (TA0043): 80% planned coverage
- [+] Initial Access (TA0001): 60% planned coverage
- [+] Execution (TA0002): 50% planned coverage
- [+] Defense Evasion (TA0005): 60% planned coverage
- [+] Credential Access (TA0006): 60% planned coverage
- [+] Discovery (TA0007): 70% planned coverage

### Developer Tools
- [+] Testing framework (pytest)
- [+] Code formatting (black)
- [+] Linting (flake8)
- [+] Type checking (mypy)
- [+] Pre-commit hooks support

### Configuration
- [+] Default configuration templates
- [+] Authorized targets file template
- [+] YAML-based configuration system
- [+] Environment variable support

## Version History

### Version Numbering

This project uses [Semantic Versioning](https://semver.org/):
- **MAJOR** version: Incompatible API changes
- **MINOR** version: New functionality (backwards compatible)
- **PATCH** version: Bug fixes (backwards compatible)

### Release Notes Format

```
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features and tools

### Changed
- Changes to existing functionality

### Deprecated
- Features that will be removed in future versions

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security fixes and improvements
```

## Upgrade Guide

### From 0.0.x to 0.1.0

Initial release - no upgrade path needed.

## Future Roadmap

### Version 0.2.0 (Target: Q1 2026)
- [X] Complete reconnaissance module with 5+ tools (DNS, Subdomain, WHOIS, Port Scanner)
- [ ] Port scanner with async support
- [X] Web security module with OWASP Top 10 tests (SQL Injection, XSS, Directory Traversal)
- [ ] Basic reporting functionality
- [X] Integration tests (reconnaissance + web security workflows)

### Version 0.3.0 (Target: Q2 2026)
- [ ] Social engineering module
- [ ] Basic exploitation tools
- [ ] Credential testing framework
- [ ] DefectDojo integration
- [ ] CI/CD pipeline

### Version 0.4.0 (Target: Q3 2026)
- [ ] Post-exploitation tools
- [ ] Lateral movement testing
- [ ] Evasion techniques
- [ ] Docker deployment
- [ ] Cloud security testing (AWS, Azure)

### Version 1.0.0 (Target: Q4 2026)
- [ ] Complete MITRE ATT&CK coverage (50%+)
- [ ] C2 framework
- [ ] Comprehensive testing suite
- [ ] Full documentation
- [ ] Public release

## Breaking Changes

None yet - initial release.

## Deprecation Notices

None yet - initial release.

## Security Advisories

No security issues reported yet.

To report a security issue:
1. **DO NOT** open a public GitHub issue
2. Open a GitHub Security Advisory
3. Email maintainers with details
4. Allow 90 days for patching before public disclosure

## Contributors

- David Dashti - Initial development and architecture

## Acknowledgments

- MITRE ATT&CK Framework for technique taxonomy
- OWASP for web security testing guidelines
- PTES for penetration testing standards
- Security research community for inspiration

---

**Note**: This is a living document. All changes should be documented here before release.

For the latest unreleased changes, see the [Unreleased] section at the top.

[Unreleased]: https://github.com/yourusername/offensive-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/offensive-toolkit/releases/tag/v0.1.0
