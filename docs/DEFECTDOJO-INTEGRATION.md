# DefectDojo Integration Guide

Complete guide for integrating the Offensive Security Toolkit with DefectDojo for vulnerability management.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Usage](#usage)
- [Workflow Examples](#workflow-examples)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)

## Overview

The Offensive Security Toolkit integrates seamlessly with DefectDojo, enabling automated vulnerability tracking, remediation workflows, and compliance reporting.

### Features

- [+] Automatic scan result uploads
- [+] Create products and engagements programmatically
- [+] Map toolkit findings to DefectDojo format
- [+] Bulk upload from scan directories
- [+] Generate reports and upload in single command
- [+] Severity mapping (Critical/High/Medium/Low)
- [+] MITRE ATT&CK technique tracking

### Architecture

```
Offensive Security Toolkit
        |
        v
  Scan Results (JSON)
        |
        v
  Report Generator -----> HTML/JSON Reports
        |
        v
  DefectDojo Client -----> DefectDojo API
        |
        v
  DefectDojo Dashboard
```

## Prerequisites

### 1. DefectDojo Instance

You need access to a DefectDojo instance (hosted or self-hosted):

- **Hosted**: [DefectDojo.com](https://defectdojo.com)
- **Self-Hosted**: [Installation Guide](https://documentation.defectdojo.com/getting_started/installation/)

For this guide, we'll use the lab server instance: `http://10.143.31.115`

### 2. API Key

Generate an API key in DefectDojo:

1. Log in to DefectDojo
2. Navigate to **User Settings** → **API v2 Key**
3. Click **Generate New Key**
4. Copy the key (starts with `Token `)

### 3. Environment Configuration

Set the API key as an environment variable:

**Windows (PowerShell)**:
```powershell
$env:DEFECTDOJO_API_KEY = "your-api-key-here"
```

**Windows (Git Bash)**:
```bash
export DEFECTDOJO_API_KEY="your-api-key-here"
```

**Linux/macOS**:
```bash
export DEFECTDOJO_API_KEY="your-api-key-here"

# Make persistent
echo 'export DEFECTDOJO_API_KEY="your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

## Setup

### 1. Configuration File

Add DefectDojo settings to `config.yaml`:

```yaml
defectdojo:
  url: "http://10.143.31.115"
  api_key: null  # Use environment variable
  default_product_type: 1
  minimum_severity: "Info"
```

### 2. Test Connection

Verify connectivity:

```bash
python reporting/defectdojo_client.py --test-connection
```

Expected output:
```
[*] DefectDojo API Client
[*] URL: http://10.143.31.115
======================================================================

[*] Testing DefectDojo connection...
[+] DefectDojo connection successful
```

## Usage

### Report Generator

Generate HTML/JSON reports from scan results:

```bash
# HTML report
python reporting/report_generator.py --input-dir output/ --format html

# HTML + JSON reports
python reporting/report_generator.py --input-dir output/ \\
    --format html,json --output security_assessment
```

**Output**:
- `security_assessment.html` - Professional HTML report
- `security_assessment.json` - Machine-readable JSON report

### DefectDojo Client

#### List Products

```bash
python reporting/defectdojo_client.py --list-products
```

#### List Engagements

```bash
python reporting/defectdojo_client.py --list-engagements --product-id 1
```

#### Create Product

```bash
python reporting/defectdojo_client.py --create-product \\
    --name "Production Application" \\
    --description "Main production web application"
```

#### Create Engagement

```bash
python reporting/defectdojo_client.py --create-engagement \\
    --product-id 1 \\
    --engagement-name "Q4 2025 Penetration Test" \\
    --description "Quarterly security assessment"
```

#### Upload Single Scan

```bash
python reporting/defectdojo_client.py \\
    --engagement-id 5 \\
    --scan-file output/sqli_example_com_20251015.json \\
    --scan-type "Generic Findings Import"
```

#### Bulk Upload

Upload all scans from a directory:

```bash
python reporting/defectdojo_client.py \\
    --engagement-id 5 \\
    --scan-dir output/
```

### Unified Reporting (Recommended)

The unified CLI combines report generation and DefectDojo upload:

#### Generate Report Only

```bash
python reporting/unified_report.py \\
    --scan-dir output/ \\
    --format html,json \\
    --output pentest_report
```

#### Generate Report + Upload to Existing Engagement

```bash
python reporting/unified_report.py \\
    --scan-dir output/ \\
    --format html \\
    --defectdojo \\
    --engagement-id 5
```

#### Generate Report + Create Engagement + Upload

```bash
python reporting/unified_report.py \\
    --scan-dir output/ \\
    --format html,json \\
    --defectdojo \\
    --product-id 1 \\
    --create-engagement \\
    --engagement-name "Q4 2025 Security Assessment"
```

## Workflow Examples

### Example 1: Reconnaissance and Reporting

```bash
# Step 1: Run reconnaissance scans
python reconnaissance/dns_resolver.py --domain example.com
python reconnaissance/subdomain_enum.py --domain example.com
python reconnaissance/port_scanner.py --target 192.0.2.1 --ports common

# Step 2: Generate report and upload to DefectDojo
python reporting/unified_report.py \\
    --scan-dir output/ \\
    --format html \\
    --defectdojo \\
    --engagement-id 10
```

### Example 2: Web Security Assessment

```bash
# Step 1: Run web security scans
python web_security/sql_injection.py --url "http://example.com/search?q=test"
python web_security/xss_scanner.py --url "http://example.com/comment?text=test"
python web_security/directory_bruteforcer.py --url "http://example.com"

# Step 2: Create engagement and upload
python reporting/unified_report.py \\
    --scan-dir output/ \\
    --format html,json \\
    --output webapp_assessment \\
    --defectdojo \\
    --product-id 2 \\
    --create-engagement \\
    --engagement-name "Web Application Security Test"
```

### Example 3: Full Offensive Security Engagement

```bash
# Phase 1: Reconnaissance
python reconnaissance/dns_resolver.py --domain target.com
python reconnaissance/subdomain_enum.py --domain target.com --use-cert-transparency
python reconnaissance/whois_lookup.py --domain target.com

# Phase 2: Scanning
python reconnaissance/port_scanner.py --target 192.0.2.1 --ports 1-10000

# Phase 3: Web Security
python web_security/sql_injection.py --url "http://target.com/login" --all-types
python web_security/xss_scanner.py --url "http://target.com/search"
python web_security/directory_bruteforcer.py --url "http://target.com"

# Phase 4: Generate comprehensive report and upload
python reporting/unified_report.py \\
    --scan-dir output/ \\
    --format html,json \\
    --output full_engagement_report \\
    --defectdojo \\
    --product-id 1 \\
    --create-engagement \\
    --engagement-name "Full Security Assessment - Q4 2025"
```

## API Reference

### DefectDojoClient Class

```python
from reporting.defectdojo_client import DefectDojoClient

# Initialize client
client = DefectDojoClient(
    base_url="http://10.143.31.115",
    api_key="your-api-key"
)

# Test connection
client.test_connection()

# Create product
product = client.create_product(
    name="My Application",
    description="Production application"
)

# Create engagement
engagement = client.create_engagement(
    product_id=product["id"],
    name="Q4 2025 Pentest",
    description="Quarterly security assessment"
)

# Upload scan
result = client.upload_scan(
    engagement_id=engagement["id"],
    scan_file=Path("output/sqli_scan.json"),
    scan_type="Generic Findings Import"
)

# Bulk upload
stats = client.bulk_upload(
    engagement_id=engagement["id"],
    scan_dir=Path("output/")
)

print(f"Uploaded {stats['success']}/{stats['total']} scans")
```

### ReportGenerator Class

```python
from reporting.report_generator import ReportGenerator
from pathlib import Path

# Initialize generator
generator = ReportGenerator()

# Load scan results
scan_files = list(Path("output/").glob("*.json"))
generator.load_scan_results(scan_files)

# Generate HTML report
generator.generate_html_report(Path("report.html"))

# Generate JSON report
generator.generate_json_report(Path("report.json"))

# Access statistics
stats = generator.statistics
print(f"Total scans: {stats['total_scans']}")
print(f"Vulnerabilities: {stats['total_vulnerabilities']}")
print(f"By severity: {dict(stats['by_severity'])}")
```

## Scan Type Mappings

The toolkit automatically maps scan types to DefectDojo formats:

| Toolkit Scan | DefectDojo Scan Type |
|--------------|---------------------|
| Port Scan | Nmap Scan |
| DNS Resolution | Generic Findings Import |
| Subdomain Enumeration | Generic Findings Import |
| WHOIS Lookup | Generic Findings Import |
| SQL Injection | Generic Findings Import |
| XSS | Generic Findings Import |
| Directory Brute-force | Generic Findings Import |

## Severity Mappings

Toolkit severity levels map to DefectDojo:

| Toolkit | DefectDojo |
|---------|------------|
| critical | Critical |
| high | High |
| medium | Medium |
| low | Low |
| info | Informational |

## Troubleshooting

### Connection Errors

**Problem**: `DefectDojo connection failed`

**Solutions**:
1. Verify DefectDojo is accessible:
   ```bash
   curl http://10.143.31.115/api/v2/users/
   ```

2. Check API key is set:
   ```bash
   echo $DEFECTDOJO_API_KEY
   ```

3. Verify API key format (should start with your token):
   ```
   YOUR_TOKEN_HERE
   ```

### Upload Failures

**Problem**: `Upload failed: 400 Bad Request`

**Solutions**:
1. Check engagement ID exists:
   ```bash
   python reporting/defectdojo_client.py --list-engagements
   ```

2. Verify scan file format (must be valid JSON)

3. Check DefectDojo logs:
   ```bash
   # On lab server
   kubectl logs -n docker-services deployment/defectdojo-celery
   ```

### Permission Errors

**Problem**: `403 Forbidden`

**Solutions**:
1. Verify API key has correct permissions
2. Check user is assigned to product/engagement
3. Regenerate API key in DefectDojo UI

### Port Forwarding (if using ClusterIP)

If DefectDojo is behind a ClusterIP service:

```bash
export KUBECONFIG=~/.kube/config-lab
kubectl port-forward -n docker-services svc/defectdojo-nginx 8080:80 &
```

Then use: `--dd-url http://localhost:8080`

## Advanced Configuration

### Custom Scan Type Mapping

Edit `reporting/defectdojo_client.py`:

```python
SCAN_TYPE_MAPPINGS = {
    "port_scan": "Nmap Scan",
    "my_custom_scan": "Custom Scanner Import",
    # Add your mappings here
}
```

### Minimum Severity Filter

Only import high/critical findings:

```python
client.upload_scan(
    engagement_id=5,
    scan_file=Path("scan.json"),
    minimum_severity="High"  # Critical, High, Medium, Low, Info
)
```

### Custom Finding Import

Import findings programmatically:

```python
findings = [
    {
        "type": "SQL Injection",
        "parameter": "username",
        "confidence": "high",
        "evidence": "Error-based SQLi detected",
        "payload": "' OR '1'='1"
    }
]

client.import_findings(
    engagement_id=5,
    findings=findings
)
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Security Scan and Report

on: [push]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run Security Scans
        run: |
          python reconnaissance/port_scanner.py --target $TARGET
          python web_security/sql_injection.py --url $TARGET_URL

      - name: Upload to DefectDojo
        env:
          DEFECTDOJO_API_KEY: ${{ secrets.DEFECTDOJO_API_KEY }}
        run: |
          python reporting/unified_report.py \\
            --scan-dir output/ \\
            --format html,json \\
            --defectdojo \\
            --engagement-id ${{ secrets.ENGAGEMENT_ID }}

      - name: Archive Reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: |
            security_report.html
            security_report.json
```

## Best Practices

1. **Use Engagements**: Create separate engagements for each assessment
2. **Tag Findings**: Use DefectDojo tags to categorize findings
3. **Regular Updates**: Re-import scans to track remediation progress
4. **Severity Consistency**: Use consistent severity ratings across tools
5. **Cleanup Old Data**: Archive completed engagements
6. **API Key Security**: Never commit API keys to version control
7. **Rate Limiting**: Respect DefectDojo API rate limits (default: 100 req/hour)

## Support

- **DefectDojo Documentation**: https://documentation.defectdojo.com
- **DefectDojo GitHub**: https://github.com/DefectDojo/django-DefectDojo
- **Toolkit Issues**: https://github.com/Dashtid/offensive-toolkit/issues

---

**Last Updated**: 2025-10-15
**Version**: 1.0
