# MITRE ATT&CK Framework Mapping

## Overview

This document maps the Offensive Security Toolkit's modules and tools to the MITRE ATT&CK framework. This alignment helps security teams understand attack techniques, develop defensive strategies, and ensure comprehensive coverage of the threat landscape.

**MITRE ATT&CK Version**: 14.0 (2025)
**Last Updated**: 2025-10-15

## Framework Overview

The MITRE ATT&CK framework consists of tactics (the "why" of an attack) and techniques (the "how" of an attack). This toolkit is organized to support testing across the entire attack lifecycle.

## Tactics Coverage

| Tactic ID | Tactic Name | Toolkit Module | Coverage |
|-----------|-------------|----------------|----------|
| TA0043 | Reconnaissance | reconnaissance/ | [+] High |
| TA0042 | Resource Development | scanning/, payload-development/ | [+] High |
| TA0001 | Initial Access | social-engineering/, web-security/ | [+] High |
| TA0002 | Execution | exploitation/ | [+] Medium |
| TA0003 | Persistence | post-exploitation/ | [+] Medium |
| TA0004 | Privilege Escalation | exploitation/ | [+] Medium |
| TA0005 | Defense Evasion | evasion/, payload-development/ | [+] Medium |
| TA0006 | Credential Access | post-exploitation/ | [+] Medium |
| TA0007 | Discovery | reconnaissance/, scanning/ | [+] High |
| TA0008 | Lateral Movement | post-exploitation/ | [+] Low |
| TA0009 | Collection | post-exploitation/ | [+] Low |
| TA0011 | Command and Control | (Future: C2 module) | [-] Planned |
| TA0010 | Exfiltration | post-exploitation/ | [+] Low |
| TA0040 | Impact | (Not implemented - defensive focus) | [-] N/A |

**Coverage Legend**:
- [+] High: Multiple tools covering most techniques
- [+] Medium: Some tools covering key techniques
- [+] Low: Basic coverage, needs expansion
- [-] Planned: Future implementation
- [-] N/A: Not applicable for defensive toolkit

---

## Detailed Technique Mapping

### TA0043: Reconnaissance

Tools for gathering information about target systems, organizations, and infrastructure.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1589 | Gather Victim Identity Information | reconnaissance/osint_tools.py | Planned |
| T1589.001 | Credentials | reconnaissance/credential_search.py | Planned |
| T1589.002 | Email Addresses | reconnaissance/email_harvester.py | Planned |
| T1590 | Gather Victim Network Information | reconnaissance/domain_enum.py | Planned |
| T1590.001 | Domain Properties | reconnaissance/domain_enum.py | Planned |
| T1590.002 | DNS | reconnaissance/dns_recon.py | Planned |
| T1590.005 | IP Addresses | reconnaissance/ip_enum.py | Planned |
| T1591 | Gather Victim Org Information | reconnaissance/osint_tools.py | Planned |
| T1592 | Gather Victim Host Information | reconnaissance/host_discovery.py | Planned |
| T1595 | Active Scanning | scanning/vuln_scanner.py | Planned |
| T1595.001 | Scanning IP Blocks | reconnaissance/network_mapper.py | Planned |
| T1595.002 | Vulnerability Scanning | scanning/vuln_scanner.py | Planned |
| T1596 | Search Open Technical Databases | reconnaissance/osint_tools.py | Planned |
| T1596.001 | DNS/Passive DNS | reconnaissance/passive_dns.py | Planned |
| T1596.005 | Scan Databases | reconnaissance/shodan_search.py | Planned |
| T1597 | Search Closed Sources | reconnaissance/dark_web_intel.py | Planned |
| T1598 | Phishing for Information | social-engineering/info_phishing.py | Planned |

**Module**: `reconnaissance/`
**Purpose**: Information gathering without directly interacting with target systems
**Authorization Level**: Medium - Still requires authorization for OSINT on private entities

---

### TA0042: Resource Development

Tools for establishing resources to support operations.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1583 | Acquire Infrastructure | (Not implemented - external) | N/A |
| T1586 | Compromise Accounts | (Not implemented - defensive focus) | N/A |
| T1587 | Develop Capabilities | payload-development/ | Planned |
| T1587.001 | Malware | payload-development/malware_dev.py | Planned |
| T1587.002 | Code Signing Certificates | (Not implemented) | N/A |
| T1587.003 | Digital Certificates | (Not implemented) | N/A |
| T1587.004 | Exploits | exploitation/exploit_dev.py | Planned |
| T1588 | Obtain Capabilities | (External tools) | N/A |
| T1608 | Stage Capabilities | payload-development/staging.py | Planned |

**Module**: `payload-development/`
**Purpose**: Creating custom payloads and exploits for testing
**Authorization Level**: High - Only on authorized test systems

---

### TA0001: Initial Access

Tools for gaining initial foothold in target systems.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1189 | Drive-by Compromise | web-security/drive_by_test.py | Planned |
| T1190 | Exploit Public-Facing Application | web-security/app_exploiter.py | Planned |
| T1133 | External Remote Services | (Testing only) | Planned |
| T1200 | Hardware Additions | (Physical security - out of scope) | N/A |
| T1566 | Phishing | social-engineering/phishing.py | Planned |
| T1566.001 | Spearphishing Attachment | social-engineering/spearphishing.py | Planned |
| T1566.002 | Spearphishing Link | social-engineering/phishing_link.py | Planned |
| T1566.003 | Spearphishing via Service | social-engineering/service_phishing.py | Planned |
| T1091 | Replication Through Removable Media | (Out of scope) | N/A |
| T1195 | Supply Chain Compromise | (Detection only) | Planned |
| T1199 | Trusted Relationship | (Testing only) | Planned |
| T1078 | Valid Accounts | (Authentication testing) | Planned |

**Modules**: `social-engineering/`, `web-security/`
**Purpose**: Testing initial access vectors
**Authorization Level**: Very High - Requires explicit permission and scope definition

---

### TA0002: Execution

Tools for running malicious code on target systems.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1059 | Command and Scripting Interpreter | exploitation/reverse_shell.py | In Progress |
| T1059.001 | PowerShell | exploitation/powershell_exec.py | Planned |
| T1059.003 | Windows Command Shell | exploitation/cmd_exec.py | Planned |
| T1059.004 | Unix Shell | exploitation/bash_exec.py | Planned |
| T1059.005 | Visual Basic | exploitation/vba_exec.py | Planned |
| T1059.006 | Python | exploitation/python_exec.py | Planned |
| T1059.007 | JavaScript | exploitation/js_exec.py | Planned |
| T1203 | Exploitation for Client Execution | exploitation/client_exploit.py | Planned |
| T1204 | User Execution | social-engineering/user_exec.py | Planned |
| T1204.001 | Malicious Link | social-engineering/malicious_link.py | Planned |
| T1204.002 | Malicious File | social-engineering/malicious_file.py | Planned |
| T1053 | Scheduled Task/Job | post-exploitation/scheduled_tasks.py | Planned |
| T1569 | System Services | post-exploitation/service_exec.py | Planned |

**Module**: `exploitation/`
**Purpose**: Testing code execution capabilities
**Authorization Level**: Very High - Only in controlled environments

---

### TA0003: Persistence

Tools for maintaining access to compromised systems.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1098 | Account Manipulation | post-exploitation/account_manip.py | Planned |
| T1136 | Create Account | post-exploitation/create_account.py | Planned |
| T1543 | Create or Modify System Process | post-exploitation/system_process.py | Planned |
| T1546 | Event Triggered Execution | post-exploitation/event_trigger.py | Planned |
| T1053 | Scheduled Task/Job | post-exploitation/persistence_scheduled.py | Planned |
| T1547 | Boot or Logon Autostart Execution | post-exploitation/autostart.py | Planned |
| T1037 | Boot or Logon Initialization Scripts | post-exploitation/init_scripts.py | Planned |
| T1176 | Browser Extensions | post-exploitation/browser_ext.py | Planned |
| T1554 | Compromise Client Software Binary | (Advanced - planned) | Planned |

**Module**: `post-exploitation/`
**Purpose**: Testing persistence mechanisms
**Authorization Level**: Very High - Requires cleanup procedures

---

### TA0004: Privilege Escalation

Tools for gaining higher-level permissions.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1548 | Abuse Elevation Control Mechanism | exploitation/elevation_abuse.py | Planned |
| T1548.002 | Bypass User Account Control | exploitation/uac_bypass.py | Planned |
| T1068 | Exploitation for Privilege Escalation | exploitation/privesc_exploit.py | Planned |
| T1134 | Access Token Manipulation | post-exploitation/token_manip.py | Planned |
| T1055 | Process Injection | exploitation/process_injection.py | Planned |
| T1078 | Valid Accounts | (Authentication testing) | Planned |
| T1053 | Scheduled Task/Job | post-exploitation/scheduled_privesc.py | Planned |

**Module**: `exploitation/`
**Purpose**: Testing privilege escalation vectors
**Authorization Level**: Very High - Can damage systems if misused

---

### TA0005: Defense Evasion

Tools for avoiding detection by security products.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1027 | Obfuscated Files or Information | evasion/obfuscation.py | Planned |
| T1027.002 | Software Packing | payload-development/packer.py | Planned |
| T1140 | Deobfuscate/Decode Files or Information | evasion/decoder.py | Planned |
| T1562 | Impair Defenses | evasion/av_disable.py | Planned |
| T1562.001 | Disable or Modify Tools | evasion/security_tools.py | Planned |
| T1070 | Indicator Removal | evasion/log_cleanup.py | Planned |
| T1070.001 | Clear Windows Event Logs | evasion/eventlog_clear.py | Planned |
| T1070.004 | File Deletion | evasion/file_wipe.py | Planned |
| T1202 | Indirect Command Execution | evasion/indirect_exec.py | Planned |
| T1055 | Process Injection | evasion/process_inject.py | Planned |
| T1620 | Reflective Code Loading | evasion/reflective_load.py | Planned |
| T1218 | System Binary Proxy Execution | evasion/lolbins.py | Planned |
| T1497 | Virtualization/Sandbox Evasion | evasion/sandbox_detect.py | Planned |

**Modules**: `evasion/`, `payload-development/`
**Purpose**: Testing detection and prevention capabilities
**Authorization Level**: High - Requires security team coordination

---

### TA0006: Credential Access

Tools for stealing credentials and authentication material.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1110 | Brute Force | post-exploitation/brute_force.py | Planned |
| T1110.001 | Password Guessing | post-exploitation/password_guess.py | Planned |
| T1110.002 | Password Cracking | post-exploitation/hash_crack.py | Planned |
| T1110.003 | Password Spraying | post-exploitation/password_spray.py | Planned |
| T1555 | Credentials from Password Stores | post-exploitation/password_stores.py | Planned |
| T1555.003 | Credentials from Web Browsers | post-exploitation/browser_creds.py | Planned |
| T1212 | Exploitation for Credential Access | post-exploitation/cred_exploit.py | Planned |
| T1056 | Input Capture | post-exploitation/keylogger.py | Planned |
| T1056.001 | Keylogging | post-exploitation/keylogger.py | Planned |
| T1003 | OS Credential Dumping | post-exploitation/credential_dump.py | Planned |
| T1003.001 | LSASS Memory | post-exploitation/lsass_dump.py | Planned |
| T1003.002 | Security Account Manager | post-exploitation/sam_dump.py | Planned |
| T1528 | Steal Application Access Token | post-exploitation/token_steal.py | Planned |
| T1539 | Steal Web Session Cookie | post-exploitation/cookie_steal.py | Planned |

**Module**: `post-exploitation/`
**Purpose**: Testing credential storage and protection
**Authorization Level**: Very High - Handles sensitive credentials

---

### TA0007: Discovery

Tools for learning about the target environment.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1087 | Account Discovery | reconnaissance/account_enum.py | Planned |
| T1087.001 | Local Account | reconnaissance/local_accounts.py | Planned |
| T1087.002 | Domain Account | reconnaissance/domain_accounts.py | Planned |
| T1083 | File and Directory Discovery | reconnaissance/file_discovery.py | Planned |
| T1046 | Network Service Discovery | reconnaissance/port_scanner.py | In Progress |
| T1135 | Network Share Discovery | reconnaissance/share_enum.py | Planned |
| T1040 | Network Sniffing | reconnaissance/packet_capture.py | Planned |
| T1201 | Password Policy Discovery | reconnaissance/password_policy.py | Planned |
| T1057 | Process Discovery | reconnaissance/process_enum.py | Planned |
| T1018 | Remote System Discovery | reconnaissance/remote_discovery.py | Planned |
| T1082 | System Information Discovery | reconnaissance/sysinfo.py | Planned |
| T1016 | System Network Configuration Discovery | reconnaissance/network_config.py | Planned |
| T1049 | System Network Connections Discovery | reconnaissance/netstat.py | Planned |
| T1033 | System Owner/User Discovery | reconnaissance/user_enum.py | Planned |
| T1007 | System Service Discovery | reconnaissance/service_enum.py | Planned |

**Modules**: `reconnaissance/`, `scanning/`
**Purpose**: Environmental reconnaissance and mapping
**Authorization Level**: Medium - Can be noisy and detectable

---

### TA0008: Lateral Movement

Tools for moving through the target environment.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1210 | Exploitation of Remote Services | post-exploitation/remote_exploit.py | Planned |
| T1534 | Internal Spearphishing | social-engineering/internal_phish.py | Planned |
| T1570 | Lateral Tool Transfer | post-exploitation/tool_transfer.py | Planned |
| T1021 | Remote Services | post-exploitation/remote_services.py | Planned |
| T1021.001 | Remote Desktop Protocol | post-exploitation/rdp_lateral.py | Planned |
| T1021.002 | SMB/Windows Admin Shares | post-exploitation/smb_lateral.py | Planned |
| T1021.004 | SSH | post-exploitation/ssh_lateral.py | Planned |
| T1021.006 | Windows Remote Management | post-exploitation/winrm_lateral.py | Planned |
| T1080 | Taint Shared Content | post-exploitation/share_taint.py | Planned |

**Module**: `post-exploitation/`
**Purpose**: Testing lateral movement detection
**Authorization Level**: Very High - Can spread beyond intended scope

---

### TA0009: Collection

Tools for gathering information of interest.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1560 | Archive Collected Data | post-exploitation/data_archive.py | Planned |
| T1119 | Automated Collection | post-exploitation/auto_collect.py | Planned |
| T1115 | Clipboard Data | post-exploitation/clipboard_capture.py | Planned |
| T1530 | Data from Cloud Storage Object | (Cloud module - planned) | Planned |
| T1005 | Data from Local System | post-exploitation/local_data.py | Planned |
| T1039 | Data from Network Shared Drive | post-exploitation/share_data.py | Planned |
| T1025 | Data from Removable Media | post-exploitation/removable_data.py | Planned |
| T1074 | Data Staged | post-exploitation/data_staging.py | Planned |
| T1056 | Input Capture | post-exploitation/input_capture.py | Planned |
| T1113 | Screen Capture | post-exploitation/screenshot.py | Planned |

**Module**: `post-exploitation/`
**Purpose**: Testing data collection detection
**Authorization Level**: Very High - May collect sensitive data

---

### TA0010: Exfiltration

Tools for stealing data from the target environment.

| Technique ID | Technique Name | Toolkit Tool | Status |
|--------------|----------------|--------------|--------|
| T1020 | Automated Exfiltration | post-exploitation/auto_exfil.py | Planned |
| T1030 | Data Transfer Size Limits | post-exploitation/chunked_exfil.py | Planned |
| T1048 | Exfiltration Over Alternative Protocol | post-exploitation/alt_exfil.py | Planned |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | post-exploitation/unencrypted_exfil.py | Planned |
| T1041 | Exfiltration Over C2 Channel | (C2 module - planned) | Planned |
| T1011 | Exfiltration Over Other Network Medium | post-exploitation/network_exfil.py | Planned |
| T1052 | Exfiltration Over Physical Medium | (Physical - out of scope) | N/A |
| T1567 | Exfiltration Over Web Service | post-exploitation/web_exfil.py | Planned |
| T1029 | Scheduled Transfer | post-exploitation/scheduled_exfil.py | Planned |
| T1537 | Transfer Data to Cloud Account | (Cloud module - planned) | Planned |

**Module**: `post-exploitation/`
**Purpose**: Testing data loss prevention (DLP) capabilities
**Authorization Level**: Very High - Must not actually exfiltrate data

---

## Coverage Analysis

### Current Implementation Status

```
Total MITRE ATT&CK Techniques Covered: ~120 techniques
Implemented: 2 (port_scanner, reverse_shell templates)
In Progress: 2
Planned: ~116

Coverage by Tactic:
├── Reconnaissance (TA0043):        [########..] 80% Planned
├── Resource Development (TA0042):  [####......] 40% Planned
├── Initial Access (TA0001):        [######....] 60% Planned
├── Execution (TA0002):            [#####.....] 50% Planned
├── Persistence (TA0003):          [####......] 40% Planned
├── Privilege Escalation (TA0004):  [####......] 40% Planned
├── Defense Evasion (TA0005):      [######....] 60% Planned
├── Credential Access (TA0006):    [######....] 60% Planned
├── Discovery (TA0007):            [#######...] 70% Planned
├── Lateral Movement (TA0008):     [###.......] 30% Planned
├── Collection (TA0009):           [####......] 40% Planned
├── Command & Control (TA0011):    [..........] 0% Planned
├── Exfiltration (TA0010):         [####......] 40% Planned
└── Impact (TA0040):               [..........] 0% N/A
```

### Priority Development Areas

**High Priority** (Next 3 months):
1. Reconnaissance tools (T1589-T1598)
2. Web security testing (T1190, OWASP Top 10)
3. Basic exploitation (T1059, T1203)
4. Credential testing (T1110, T1003)

**Medium Priority** (3-6 months):
1. Social engineering (T1566)
2. Defense evasion (T1027, T1562)
3. Post-exploitation (T1003, T1087)
4. Lateral movement (T1021)

**Low Priority** (6-12 months):
1. C2 framework (TA0011)
2. Advanced persistence (T1543, T1546)
3. Cloud security testing
4. Container security

## Usage Guidelines

### Mapping Your Tests

When conducting a penetration test:

1. **Define Scope**: Select which MITRE tactics apply to your engagement
2. **Choose Techniques**: Identify specific techniques to test
3. **Select Tools**: Use toolkit modules mapped to those techniques
4. **Document Results**: Map findings back to MITRE ATT&CK IDs
5. **Report Impact**: Show which tactics/techniques were successful

### Example Test Plan

```yaml
engagement_name: "Internal Network Assessment"
scope:
  - Reconnaissance (TA0043)
  - Initial Access (TA0001)
  - Discovery (TA0007)

techniques:
  - T1046: Network Service Discovery
    tool: reconnaissance/port_scanner.py
  - T1190: Exploit Public-Facing Application
    tool: web-security/app_exploiter.py
  - T1110: Brute Force
    tool: post-exploitation/brute_force.py

success_criteria:
  - Identify all internet-facing services
  - Test authentication on web applications
  - Document privilege escalation paths
```

## Defensive Countermeasures

For each technique tested, consider these defensive measures:

### Detection
- Log analysis for technique indicators
- Behavioral analytics for anomalies
- Network traffic monitoring

### Prevention
- Patch vulnerable services
- Implement least privilege
- Network segmentation

### Response
- Incident response playbooks
- Automated containment
- Threat hunting procedures

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK for ICS](https://collaborate.mitre.org/attackics/)
- [D3FEND Framework](https://d3fend.mitre.org/)

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2025-10-15 | Initial MITRE mapping created |

---

**Maintained By**: David Dashti
**Framework Version**: MITRE ATT&CK v14.0
**Last Review**: 2025-10-15
