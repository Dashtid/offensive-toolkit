#!/usr/bin/env python3
"""
Report Generator - Security Testing Reports

Generates professional security testing reports from scan results with support
for multiple formats (HTML, PDF, JSON, CSV) and visualization.

[!] CONFIDENTIAL: Reports contain sensitive security information.

Usage:
    python report_generator.py --input-dir <output/> --format html,pdf
    python report_generator.py --scan-files scan1.json scan2.json --format html

Examples:
    # Generate HTML report from all scans
    python report_generator.py --input-dir output/ --format html

    # Generate HTML + PDF report
    python report_generator.py --input-dir output/ --format html,pdf --output report

    # Generate report from specific scans
    python report_generator.py --scan-files output/dns_*.json output/sqli_*.json

Author: David Dashti
Date: 2025-10-15
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from utils.config import load_config
from utils.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """
    Generate comprehensive security testing reports.

    Supports multiple scan types and output formats.
    """

    # Severity mapping for vulnerabilities
    SEVERITY_SCORES = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

    # MITRE ATT&CK tactics
    MITRE_TACTICS = {
        "TA0043": "Reconnaissance",
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0011": "Command and Control",
        "TA0040": "Impact",
    }

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize report generator."""
        self.config = config or load_config()
        self.scan_results = []
        self.vulnerabilities = []
        self.statistics = {
            "total_scans": 0,
            "total_vulnerabilities": 0,
            "by_severity": defaultdict(int),
            "by_type": defaultdict(int),
            "targets": set(),
            "techniques": set(),
        }
        logger.info("Initialized ReportGenerator")

    def load_scan_results(self, scan_files: list[Path]) -> None:
        """
        Load scan results from JSON files.

        Args:
            scan_files: List of scan result file paths
        """
        for scan_file in scan_files:
            try:
                with open(scan_file) as f:
                    data = json.load(f)

                self.scan_results.append(
                    {
                        "file": scan_file.name,
                        "data": data,
                        "type": self._detect_scan_type(scan_file.name, data),
                    }
                )

                self.statistics["total_scans"] += 1
                self._extract_statistics(data)

                logger.info(f"Loaded scan results from {scan_file.name}")

            except Exception as e:
                logger.error(f"Error loading {scan_file}: {e}")

    def _detect_scan_type(self, filename: str, data: dict[str, Any]) -> str:
        """Detect scan type from filename and data."""
        if "dns_" in filename or "domain" in data:
            return "DNS Resolution"
        if "subdomains_" in filename or "subdomains" in data:
            return "Subdomain Enumeration"
        if "whois_" in filename or ("parsed" in data and "registrar" in data.get("parsed", {})):
            return "WHOIS Lookup"
        if "portscan_" in filename or "total_ports_scanned" in data:
            return "Port Scan"
        if "sqli_" in filename or "injection_types" in data:
            return "SQL Injection"
        if "xss_" in filename or "payloads_tested" in data:
            return "XSS Scan"
        if "directory_" in filename or "wordlist" in data:
            return "Directory Brute-force"
        return "Unknown Scan"

    def _extract_statistics(self, data: dict[str, Any]) -> None:
        """Extract statistics from scan data."""
        # Extract target
        for key in ["target", "url", "domain"]:
            if key in data:
                self.statistics["targets"].add(str(data[key]))
                break

        # Extract vulnerabilities
        if "vulnerabilities" in data:
            vulns = data["vulnerabilities"]
            if isinstance(vulns, list):
                self.statistics["total_vulnerabilities"] += len(vulns)

                for vuln in vulns:
                    # Severity
                    severity = vuln.get("confidence", "low").lower()
                    self.statistics["by_severity"][severity] += 1

                    # Type
                    vuln_type = vuln.get("type", "unknown")
                    self.statistics["by_type"][vuln_type] += 1

                    # Store full vulnerability
                    self.vulnerabilities.append(vuln)

        # Extract open ports
        if "results" in data and "total_ports_scanned" in data:
            open_ports = [p for p, info in data["results"].items() if info.get("status") == "open"]
            if open_ports:
                self.statistics["by_type"]["open_port"] += len(open_ports)

        # Extract subdomains
        if "subdomains" in data:
            count = len(data.get("subdomains", []))
            if count > 0:
                self.statistics["by_type"]["subdomain"] += count

    def generate_html_report(self, output_path: Path) -> bool:
        """
        Generate comprehensive HTML report.

        Args:
            output_path: Output file path

        Returns:
            True if successful
        """
        html = self._generate_html_content()

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)
            logger.info(f"HTML report generated: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error writing HTML report: {e}")
            return False

    def _generate_html_content(self) -> str:
        """Generate HTML report content."""
        # Generate sections
        executive_summary = self._generate_executive_summary_html()
        vulnerability_summary = self._generate_vulnerability_summary_html()
        scan_details = self._generate_scan_details_html()
        recommendations = self._generate_recommendations_html()

        # Generate charts (base64 embedded)
        severity_chart = self._generate_severity_chart()

        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
            margin: -20px -20px 30px -20px;
        }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .warning {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }}
        .section {{
            margin: 30px 0;
            padding: 20px;
            background: #f9f9f9;
            border-radius: 8px;
        }}
        h2 {{
            color: #667eea;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #667eea;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{ background-color: #f5f5f5; }}
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        .severity-critical {{
            background: #dc3545;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .severity-high {{
            background: #fd7e14;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .severity-medium {{
            background: #ffc107;
            color: #333;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .severity-low {{
            background: #28a745;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .chart-container {{
            text-align: center;
            margin: 30px 0;
        }}
        .chart-container img {{
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        ul {{
            margin: 15px 0;
            padding-left: 20px;
        }}
        li {{
            margin: 10px 0;
        }}
        footer {{
            margin-top: 40px;
            padding: 20px;
            background: #f5f5f5;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
        .scan-type {{
            display: inline-block;
            background: #e9ecef;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            margin: 2px;
        }}
        @media print {{
            .container {{ box-shadow: none; }}
            header {{ background: #667eea; }}
            .section {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Assessment Report</h1>
            <p>Offensive Security Toolkit</p>
            <p>{date}</p>
        </header>

        <div class="warning">
            <strong>[!] CONFIDENTIAL</strong> - This report contains sensitive security information.
            For authorized personnel only. Handle according to your organization's data classification policy.
        </div>

        {executive_summary}

        {vulnerability_summary}

        {severity_chart}

        {scan_details}

        {recommendations}

        <footer>
            <p><strong>Generated by Offensive Security Toolkit</strong></p>
            <p>{date}</p>
            <p>Report ID: {report_id}</p>
        </footer>
    </div>
</body>
</html>
"""

        return html_template.format(
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            report_id=datetime.now().strftime("%Y%m%d%H%M%S"),
            executive_summary=executive_summary,
            vulnerability_summary=vulnerability_summary,
            severity_chart=severity_chart,
            scan_details=scan_details,
            recommendations=recommendations,
        )

    def _generate_executive_summary_html(self) -> str:
        """Generate executive summary section."""
        targets = (
            ", ".join(sorted(self.statistics["targets"]))
            if self.statistics["targets"]
            else "Multiple targets"
        )

        return f"""
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="stat-number">{self.statistics["total_scans"]}</div>
                    <div class="stat-label">Total Scans</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{self.statistics["total_vulnerabilities"]}</div>
                    <div class="stat-label">Vulnerabilities Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(self.statistics["targets"])}</div>
                    <div class="stat-label">Targets Assessed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(self.statistics["by_type"])}</div>
                    <div class="stat-label">Finding Types</div>
                </div>
            </div>
            <p><strong>Targets:</strong> {targets}</p>
            <p><strong>Assessment Period:</strong> {datetime.now().strftime("%Y-%m-%d")}</p>
        </div>
        """

    def _generate_vulnerability_summary_html(self) -> str:
        """Generate vulnerability summary table."""
        if not self.vulnerabilities:
            return """
            <div class="section">
                <h2>Vulnerability Summary</h2>
                <p>No vulnerabilities detected in this assessment.</p>
            </div>
            """

        # Sort by severity
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: self.SEVERITY_SCORES.get(v.get("confidence", "low").lower(), 0),
            reverse=True,
        )

        rows = []
        for i, vuln in enumerate(sorted_vulns[:50], 1):  # Limit to top 50
            severity = vuln.get("confidence", "low").lower()
            vuln_type = vuln.get("type", "Unknown")
            parameter = vuln.get("parameter", vuln.get("sink", "N/A"))
            evidence = vuln.get("evidence", "No details")[:100]

            rows.append(f"""
                <tr>
                    <td>{i}</td>
                    <td>{vuln_type}</td>
                    <td><span class="severity-{severity}">{severity.upper()}</span></td>
                    <td>{parameter}</td>
                    <td>{evidence}...</td>
                </tr>
            """)

        return f"""
        <div class="section">
            <h2>Vulnerability Summary</h2>
            <p>Found <strong>{len(self.vulnerabilities)}</strong> potential vulnerabilities
               (showing top 50)</p>
            <table>
                <tr>
                    <th>#</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Location</th>
                    <th>Evidence</th>
                </tr>
                {"".join(rows)}
            </table>
        </div>
        """

    def _generate_scan_details_html(self) -> str:
        """Generate detailed scan results."""
        sections = []

        for scan in self.scan_results:
            scan_type = scan["type"]
            data = scan["data"]

            sections.append(f"""
            <div class="section">
                <h2>{scan_type}</h2>
                <p><span class="scan-type">{scan["file"]}</span></p>
                {self._format_scan_data(scan_type, data)}
            </div>
            """)

        return "\n".join(sections)

    def _format_scan_data(self, scan_type: str, data: dict[str, Any]) -> str:
        """Format scan data based on type."""
        if scan_type == "Port Scan":
            return self._format_port_scan(data)
        if scan_type == "DNS Resolution":
            return self._format_dns_scan(data)
        if scan_type == "Subdomain Enumeration":
            return self._format_subdomain_scan(data)
        if scan_type in ["SQL Injection", "XSS Scan"]:
            return self._format_vulnerability_scan(data)
        return f"<pre>{json.dumps(data, indent=2)[:500]}...</pre>"

    def _format_port_scan(self, data: dict[str, Any]) -> str:
        """Format port scan results."""
        open_ports = [
            (p, info) for p, info in data.get("results", {}).items() if info.get("status") == "open"
        ]

        if not open_ports:
            return "<p>No open ports found.</p>"

        rows = [
            f"<tr><td>{port}</td><td>{info.get('service', 'Unknown')}</td></tr>"
            for port, info in open_ports
        ]

        return f"""
        <p><strong>Target:</strong> {data.get("target", "Unknown")}</p>
        <p><strong>Open Ports:</strong> {len(open_ports)}</p>
        <table>
            <tr><th>Port</th><th>Service</th></tr>
            {"".join(rows)}
        </table>
        """

    def _format_dns_scan(self, data: dict[str, Any]) -> str:
        """Format DNS scan results."""
        records = data.get("records", {})

        rows = []
        for record_type, values in records.items():
            if values:
                rows.append(f"<tr><td>{record_type}</td><td>{', '.join(values)}</td></tr>")

        return f"""
        <p><strong>Domain:</strong> {data.get("domain", "Unknown")}</p>
        <table>
            <tr><th>Record Type</th><th>Values</th></tr>
            {"".join(rows)}
        </table>
        """

    def _format_subdomain_scan(self, data: dict[str, Any]) -> str:
        """Format subdomain scan results."""
        subdomains = data.get("subdomains", [])

        if not subdomains:
            return "<p>No subdomains found.</p>"

        subdomain_list = "<br>".join(subdomains[:50])

        return f"""
        <p><strong>Domain:</strong> {data.get("domain", "Unknown")}</p>
        <p><strong>Found:</strong> {len(subdomains)} subdomains (showing 50)</p>
        <p>{subdomain_list}</p>
        """

    def _format_vulnerability_scan(self, data: dict[str, Any]) -> str:
        """Format vulnerability scan results."""
        vulns = data.get("vulnerabilities", [])

        if not vulns:
            return "<p>No vulnerabilities detected.</p>"

        rows = []
        for vuln in vulns[:20]:
            rows.append(f"""
                <tr>
                    <td>{vuln.get("type", "Unknown")}</td>
                    <td>{vuln.get("parameter", "N/A")}</td>
                    <td><span class="severity-{vuln.get("confidence", "low").lower()}">
                        {vuln.get("confidence", "low").upper()}
                    </span></td>
                </tr>
            """)

        return f"""
        <p><strong>Target:</strong> {data.get("url", "Unknown")}</p>
        <p><strong>Vulnerabilities Found:</strong> {len(vulns)}</p>
        <table>
            <tr><th>Type</th><th>Parameter</th><th>Severity</th></tr>
            {"".join(rows)}
        </table>
        """

    def _generate_severity_chart(self) -> str:
        """Generate severity distribution chart (ASCII for now, could use matplotlib)."""
        if not self.statistics["by_severity"]:
            return ""

        # Simple HTML bar chart
        chart_html = '<div class="section"><h2>Vulnerability Distribution by Severity</h2>'
        chart_html += '<div style="margin: 20px 0;">'

        for severity in ["critical", "high", "medium", "low"]:
            count = self.statistics["by_severity"].get(severity, 0)
            percentage = (count / max(self.statistics["total_vulnerabilities"], 1)) * 100

            chart_html += f"""
            <div style="margin: 10px 0;">
                <div style="display: flex; align-items: center;">
                    <div style="width: 100px; text-align: right; padding-right: 10px;">
                        <span class="severity-{severity}">{severity.upper()}</span>
                    </div>
                    <div style="flex: 1; background: #e9ecef; border-radius: 4px; height: 30px; position: relative;">
                        <div style="background: {"#dc3545" if severity == "critical" else "#fd7e14" if severity == "high" else "#ffc107" if severity == "medium" else "#28a745"};
                                    width: {percentage}%; height: 100%; border-radius: 4px;
                                    display: flex; align-items: center; justify-content: center; color: white; font-weight: bold;">
                            {count}
                        </div>
                    </div>
                </div>
            </div>
            """

        chart_html += "</div></div>"
        return chart_html

    def _generate_recommendations_html(self) -> str:
        """Generate recommendations based on findings."""
        recommendations = [
            "Remediate all critical and high severity vulnerabilities immediately",
            "Implement input validation and output encoding to prevent injection attacks",
            "Configure security headers (CSP, X-Frame-Options, HSTS) on all web applications",
            "Enforce strong authentication mechanisms and enable multi-factor authentication",
            "Keep all systems and software up to date with security patches",
            "Implement network segmentation and principle of least privilege",
            "Conduct regular security assessments and penetration testing",
            "Establish a vulnerability management program with defined SLAs",
            "Implement security monitoring and logging for detection capabilities",
            "Provide security awareness training for development and operations teams",
        ]

        rec_list = "\n".join([f"<li>{rec}</li>" for rec in recommendations])

        return f"""
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                {rec_list}
            </ul>
        </div>
        """

    def generate_json_report(self, output_path: Path) -> bool:
        """Generate JSON report."""
        report_data = {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "toolkit": "Offensive Security Toolkit",
                "version": "0.2.0",
            },
            "statistics": {
                "total_scans": self.statistics["total_scans"],
                "total_vulnerabilities": self.statistics["total_vulnerabilities"],
                "by_severity": dict(self.statistics["by_severity"]),
                "by_type": dict(self.statistics["by_type"]),
                "targets": list(self.statistics["targets"]),
            },
            "vulnerabilities": self.vulnerabilities,
            "scans": [
                {"file": scan["file"], "type": scan["type"], "data": scan["data"]}
                for scan in self.scan_results
            ],
        }

        try:
            with open(output_path, "w") as f:
                json.dump(report_data, f, indent=2)
            logger.info(f"JSON report generated: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error writing JSON report: {e}")
            return False


def main() -> int:
    """Main entry point for command-line usage."""
    parser = argparse.ArgumentParser(
        description="Report Generator - Security Testing Reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--input-dir", type=Path, help="Directory containing scan result files")

    parser.add_argument("--scan-files", nargs="+", type=Path, help="Specific scan files to include")

    parser.add_argument(
        "--format", default="html", help="Output format: html, json, or html,json (comma-separated)"
    )

    parser.add_argument(
        "--output", default="security_report", help="Output filename (without extension)"
    )

    parser.add_argument("--config", help="Path to configuration file")

    args = parser.parse_args()

    if not args.input_dir and not args.scan_files:
        parser.error("Either --input-dir or --scan-files is required")

    # Load configuration
    config = load_config(args.config) if args.config else load_config()

    print("\n" + "=" * 70)
    print("[*] Security Report Generator")
    print("=" * 70 + "\n")

    # Initialize generator
    generator = ReportGenerator(config)

    # Collect scan files
    scan_files = []
    if args.input_dir:
        if not args.input_dir.exists():
            print(f"[-] Error: Directory {args.input_dir} does not exist")
            return 1
        scan_files = list(args.input_dir.glob("*.json"))
    elif args.scan_files:
        scan_files = [f for f in args.scan_files if f.exists()]

    if not scan_files:
        print("[-] No scan files found")
        return 1

    print(f"[*] Found {len(scan_files)} scan result files")

    # Load scan results
    generator.load_scan_results(scan_files)

    # Generate reports
    formats = args.format.split(",")
    success = True

    for fmt in formats:
        fmt = fmt.strip().lower()
        output_path = Path(f"{args.output}.{fmt}")

        if fmt == "html":
            print("[*] Generating HTML report...")
            success = generator.generate_html_report(output_path) and success
            if success:
                print(f"[+] HTML report: {output_path}")

        elif fmt == "json":
            print("[*] Generating JSON report...")
            success = generator.generate_json_report(output_path) and success
            if success:
                print(f"[+] JSON report: {output_path}")

        else:
            print(f"[-] Unknown format: {fmt}")
            success = False

    # Print summary
    print("\n[+] Report Summary:")
    print(f"    Total Scans: {generator.statistics['total_scans']}")
    print(f"    Vulnerabilities: {generator.statistics['total_vulnerabilities']}")
    print(f"    Targets: {len(generator.statistics['targets'])}")

    if generator.statistics["by_severity"]:
        print("\n[+] By Severity:")
        for severity in ["critical", "high", "medium", "low"]:
            count = generator.statistics["by_severity"].get(severity, 0)
            if count > 0:
                print(f"    {severity.upper()}: {count}")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
