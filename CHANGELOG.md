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

- **Reporting & Vulnerability Management**:
  - [+] report_generator.py (780+ lines) - Professional HTML/JSON report generation
    - Executive summary with statistics dashboard
    - Vulnerability summary table sorted by severity
    - Detailed scan results with automatic type detection
    - Severity distribution charts (HTML bar charts)
    - Comprehensive CSS styling with gradient headers and print-friendly layouts
    - Supports all scan types: DNS, subdomain, port scan, WHOIS, SQLi, XSS, directory
  - [+] defectdojo_client.py (570+ lines) - Full DefectDojo API integration
    - Create products and engagements programmatically
    - Upload scan results with automatic type detection
    - Bulk upload from scan directories
    - Import findings directly via API with severity mapping
    - Connection testing and authentication
    - List products, engagements, and findings
  - [+] unified_report.py (230+ lines) - All-in-one reporting CLI
    - Generate HTML/JSON reports from scan directory
    - Upload to DefectDojo in single command
    - Two-phase workflow: Report generation → DefectDojo upload
    - Auto-create engagements with metadata
    - Complete statistics and summaries
  - [+] docs/DEFECTDOJO-INTEGRATION.md - Comprehensive integration guide
    - Setup instructions and prerequisites
    - Workflow examples for reconnaissance and web security
    - API reference and troubleshooting
    - CI/CD integration examples

- **Cloud Security Tools** (MITRE TA0042, TA0007):
  - [+] aws_scanner.py (600+ lines) - AWS security misconfiguration scanner
    - IAM user and role analysis (MFA, access keys, admin policies) (T1087.004)
    - S3 bucket public exposure and encryption (T1530)
    - Security group overly permissive rules (T1046)
    - EC2 instance security (IMDSv2, EBS encryption) (T1580, T1552.005)
    - CloudTrail logging configuration (T1562.008)
  - [+] azure_scanner.py (620+ lines) - Azure security misconfiguration scanner
    - Storage account HTTPS enforcement and public blob access (T1530)
    - Network Security Group (NSG) public access rules (T1046)
    - Virtual machine public IPs and disk encryption (T1580)
    - Public IP and DDoS protection analysis
    - Managed disk encryption validation
  - [+] gcp_scanner.py (650+ lines) - GCP security misconfiguration scanner
    - GCS bucket public access and uniform bucket-level access (T1530)
    - VPC firewall rules allowing 0.0.0.0/0 (T1046)
    - Compute Engine instances with public IPs (T1580)
    - Default service account usage detection (T1078.004)
    - Persistent disk encryption (CMEK) validation
  - [+] cloud_cli.py (270+ lines) - Unified multi-cloud scanner
    - Parallel scanning of AWS, Azure, and GCP
    - Unified findings format and aggregated metrics
    - Cross-cloud security comparison

- **API Security Tools** (MITRE T1190):
  - [+] api_fuzzer.py (750+ lines) - OWASP API Security Top 10 2023 fuzzer
    - API1:2023 - BOLA/IDOR detection (horizontal privilege escalation)
    - API2:2023 - Broken authentication testing (rate limiting, weak passwords, JWT)
    - API3:2023 - Excessive data exposure detection (sensitive field analysis)
    - API4:2023 - Unrestricted resource consumption (rate limiting tests)
    - API5:2023 - BFLA detection (function-level authorization bypass)
    - API7:2023 - SSRF testing (internal resource access, metadata endpoints)
    - API8:2023 - Security misconfiguration (missing headers, CORS, verbose errors)
  - [+] graphql_scanner.py (520+ lines) - GraphQL security scanner
    - Introspection query testing (schema disclosure)
    - Query depth attack detection (nested queries DoS) (T1499)
    - Batch query abuse testing (query batching DoS)
    - Alias-based DoS attacks (resource exhaustion)
    - Field suggestion enumeration (typo-based discovery)
    - Verbose error message detection (information disclosure)

- **Post-Exploitation Tools**:
  - [+] persistence.py (900+ lines) - Windows + Linux persistence mechanisms (MITRE TA0003)
    - Windows: Scheduled tasks (T1053), registry run keys (T1547), startup folder, services
    - Linux: Cron jobs (T1053), systemd services, SSH authorized_keys, shell profiles
    - Check existing persistence mechanisms
    - Install persistence with automatic logging (.persistence_log.json)
    - Cleanup all installed persistence (ethical use support)
    - Cross-platform support with OS detection
  - [+] privesc_windows.py (650+ lines) - Windows privilege escalation scanner (MITRE TA0004)
    - Unquoted service paths detection (T1574.009)
    - Weak service permissions with SDDL parsing (T1574.011)
    - Registry autorun enumeration (T1547)
    - AlwaysInstallElevated vulnerability check (T1548.002)
    - Token privileges analysis (SeImpersonate, SeDebug, SeBackup) (T1134)
    - Kernel exploit suggester (MS16-032, CVE-2021-1732, CVE-2023-21768) (T1068)
  - [+] privesc_linux.py (600+ lines) - Linux privilege escalation scanner (MITRE TA0004)
    - SUID/SGID binary scanning with GTFOBins detection (T1548.001)
    - Sudo misconfigurations (NOPASSWD, dangerous commands) (T1548.003)
    - Cron job weak permissions (T1053.003)
    - Writable critical files (/etc/passwd, /etc/shadow) (T1068)
    - Docker container escape detection (T1611)
    - Kernel exploit suggester (Dirty COW, Dirty Pipe, DirtyPipe2) (T1068)
  - [+] privesc_scanner.py (90+ lines) - Unified privilege escalation CLI
    - Auto-detects OS and runs appropriate scanner
    - JSON output for DefectDojo integration
  - [+] credential_dump.py (520+ lines) - Ethical credential harvesting (MITRE TA0006)
    - Windows: Saved credentials (cmdkey), WiFi passwords (netsh), registry credentials (T1555)
    - Linux: SSH private keys, bash history, config files, environment variables (T1552)
    - Audit logging for all operations with timestamps
    - Base64 obfuscation for sensitive data
    - Explicit authorization confirmation required
    - Restrictive file permissions (0600) on output (T1087)
  - [+] lateral_movement.py (440+ lines) - Network lateral movement scanner (MITRE TA0008)
    - Multi-protocol: SMB (445, 139), RDP (3389), SSH (22), WinRM (5985, 5986), WMI (135), VNC (5900+), Telnet (23) (T1021)
    - SMB share enumeration (Windows net view / Linux smbclient) (T1021.002)
    - Banner grabbing for service identification
    - Concurrent scanning with ThreadPoolExecutor
    - CIDR range expansion for network scanning
    - Vulnerability detection (EternalBlue, BlueKeep references) (T1570, T1550)

### Changed
- Enhanced utils modules with comprehensive test coverage
- Improved rate limiting implementation with token bucket algorithm
- Updated configuration system with better environment variable support
- Reporting infrastructure completely rewritten for professional output

### Planned
- OSINT collection tools
- Social engineering templates
- Credential testing tools
- Advanced exploitation modules
- Privilege escalation scanner

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

### Version 0.2.0 (Target: Q1 2026) - COMPLETED
- [X] Complete reconnaissance module with 5+ tools (DNS, Subdomain, WHOIS, Port Scanner)
- [ ] Port scanner with async support (deferred to 0.3.0)
- [X] Web security module with OWASP Top 10 tests (SQL Injection, XSS, Directory Traversal)
- [X] Professional reporting functionality (HTML/JSON with DefectDojo integration)
- [X] Integration tests (reconnaissance + web security workflows)
- [X] DefectDojo integration (full API client + unified reporting)
- [X] Post-exploitation tools (persistence module for Windows + Linux)

**Status**: All major features complete! 🎉

### Version 0.3.0 (Target: Q2 2026) - IN PROGRESS
- [ ] Port scanner with async support
- [X] Privilege escalation scanner (Windows + Linux)
- [X] Lateral movement tools
- [X] Cloud security testing (AWS, Azure, GCP)
- [X] API security testing framework (OWASP API Top 10 2023 + GraphQL)
- [ ] Social engineering module
- [ ] Credential testing framework
- [ ] Unit tests for reporting modules
- [ ] Unit tests for post-exploitation modules
- [ ] Post-exploitation documentation guide
- [ ] Cloud security documentation guide
- [ ] API security documentation guide

**Status**: Major cloud and API security features complete! 🎉

### Version 0.4.0 (Target: Q3 2026)
- [ ] Advanced persistence techniques
- [ ] Evasion techniques (AMSI bypass, syscall injection, obfuscation)
- [ ] AI/LLM security testing (OWASP LLM Top 10 2025, prompt injection)
- [ ] Docker deployment
- [ ] Wireless security testing

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
