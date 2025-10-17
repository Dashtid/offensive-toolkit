#!/usr/bin/env python3
"""
Unified Reporting - All-in-One Report Generation and Upload

Generates reports and optionally uploads to DefectDojo in a single command.

[!] AUTHORIZATION: Requires DefectDojo API key for uploads

Usage:
    python unified_report.py --scan-dir output/ --format html,json
    python unified_report.py --scan-dir output/ --format html --defectdojo

Examples:
    # Generate HTML + JSON reports
    python unified_report.py --scan-dir output/ --format html,json --output pentest_report

    # Generate report and upload to DefectDojo
    python unified_report.py --scan-dir output/ --format html \\
        --defectdojo --engagement-id 5

    # Create engagement and upload all scans
    python unified_report.py --scan-dir output/ --format html \\
        --defectdojo --product-id 1 --create-engagement \\
        --engagement-name "Q4 2025 Pentest"

Author: David Dashti
Date: 2025-10-15
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

from offensive_toolkit.reporting.defectdojo_client import DefectDojoClient
from offensive_toolkit.reporting.report_generator import ReportGenerator
from offensive_toolkit.utils.config import load_config
from offensive_toolkit.utils.logger import get_logger

logger = get_logger(__name__)


def main() -> int:
    """
    Unified reporting entry point.

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    parser = argparse.ArgumentParser(
        description="Unified Reporting - Generate reports and upload to DefectDojo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Input
    parser.add_argument(
        "--scan-dir", type=Path, required=True, help="Directory containing scan result files"
    )

    # Report generation
    parser.add_argument(
        "--format",
        default="html",
        help="Output formats: html, json, or html,json (comma-separated)",
    )

    parser.add_argument(
        "--output", default="security_report", help="Output filename (without extension)"
    )

    # DefectDojo integration
    parser.add_argument("--defectdojo", action="store_true", help="Upload results to DefectDojo")

    parser.add_argument("--dd-url", help="DefectDojo URL (default: from config)")

    parser.add_argument(
        "--dd-api-key", help="DefectDojo API key (default: from env DEFECTDOJO_API_KEY)"
    )

    parser.add_argument("--product-id", type=int, help="DefectDojo product ID")

    parser.add_argument("--engagement-id", type=int, help="Existing DefectDojo engagement ID")

    parser.add_argument("--create-engagement", action="store_true", help="Create new engagement")

    parser.add_argument("--engagement-name", help="Name for new engagement")

    parser.add_argument("--config", help="Path to configuration file")

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config) if args.config else load_config()

    # Set log level
    if args.verbose:
        from utils.logger import set_log_level

        set_log_level(logger, "DEBUG")

    print("\n" + "=" * 70)
    print("[*] Unified Reporting - Offensive Security Toolkit")
    print("=" * 70 + "\n")

    # Validate scan directory
    if not args.scan_dir.exists():
        print(f"[-] Error: Scan directory {args.scan_dir} does not exist")
        return 1

    scan_files = list(args.scan_dir.glob("*.json"))

    if not scan_files:
        print(f"[-] Error: No scan files found in {args.scan_dir}")
        return 1

    print(f"[*] Found {len(scan_files)} scan result files")

    # ===================
    # PHASE 1: Generate Reports
    # ===================
    print("\n[*] Phase 1: Generating Reports")
    print("=" * 70)

    generator = ReportGenerator(config)
    generator.load_scan_results(scan_files)

    # Generate reports
    formats = args.format.split(",")
    report_paths = []

    for fmt in formats:
        fmt = fmt.strip().lower()
        output_path = Path(f"{args.output}.{fmt}")

        if fmt == "html":
            print("[*] Generating HTML report...")
            if generator.generate_html_report(output_path):
                print(f"[+] HTML report: {output_path}")
                report_paths.append(output_path)
            else:
                print("[-] Failed to generate HTML report")
                return 1

        elif fmt == "json":
            print("[*] Generating JSON report...")
            if generator.generate_json_report(output_path):
                print(f"[+] JSON report: {output_path}")
                report_paths.append(output_path)
            else:
                print("[-] Failed to generate JSON report")
                return 1

        else:
            print(f"[-] Unknown format: {fmt}")
            return 1

    # Print report summary
    print("\n[+] Report Summary:")
    print(f"    Total Scans: {generator.statistics['total_scans']}")
    print(f"    Vulnerabilities: {generator.statistics['total_vulnerabilities']}")
    print(f"    Targets: {len(generator.statistics['targets'])}")

    if generator.statistics["by_severity"]:
        print("\n[+] Vulnerabilities by Severity:")
        for severity in ["critical", "high", "medium", "low"]:
            count = generator.statistics["by_severity"].get(severity, 0)
            if count > 0:
                print(f"    {severity.upper()}: {count}")

    # ===================
    # PHASE 2: Upload to DefectDojo (Optional)
    # ===================
    if args.defectdojo:
        print("\n[*] Phase 2: Uploading to DefectDojo")
        print("=" * 70)

        # Initialize DefectDojo client
        dd_client = DefectDojoClient(base_url=args.dd_url, api_key=args.dd_api_key, config=config)

        if not dd_client.api_key:
            print("[-] Error: No DefectDojo API key configured")
            print("[!] Set DEFECTDOJO_API_KEY environment variable or use --dd-api-key")
            return 1

        # Test connection
        print(f"[*] Testing DefectDojo connection to {dd_client.base_url}...")
        if not dd_client.test_connection():
            print("[-] DefectDojo connection failed")
            return 1

        print("[+] DefectDojo connection successful")

        # Create engagement if requested
        if args.create_engagement:
            if not args.product_id:
                print("[-] Error: --product-id required to create engagement")
                return 1

            if not args.engagement_name:
                args.engagement_name = f"Security Assessment {datetime.now().strftime('%Y-%m-%d')}"

            print(f"[*] Creating engagement: {args.engagement_name}")

            engagement = dd_client.create_engagement(
                product_id=args.product_id,
                name=args.engagement_name,
                description=f"Automated upload from Offensive Security Toolkit\n"
                f"Scans: {generator.statistics['total_scans']}\n"
                f"Vulnerabilities: {generator.statistics['total_vulnerabilities']}",
            )

            if engagement:
                print(f"[+] Created engagement ID: {engagement['id']}")
                args.engagement_id = engagement["id"]
            else:
                print("[-] Failed to create engagement")
                return 1

        # Validate engagement ID
        if not args.engagement_id:
            print("[-] Error: --engagement-id required for uploads")
            print(
                "[!] Use --create-engagement to create new engagement or specify existing --engagement-id"
            )
            return 1

        # Upload scans
        print(f"[*] Uploading {len(scan_files)} scans to engagement {args.engagement_id}...")

        stats = dd_client.bulk_upload(engagement_id=args.engagement_id, scan_dir=args.scan_dir)

        print("\n[+] DefectDojo Upload Summary:")
        print(f"    Total Files: {stats['total']}")
        print(f"    Successful: {stats['success']}")
        print(f"    Failed: {stats['failed']}")

        if stats["failed"] > 0:
            print("\n[!] Warning: Some uploads failed (see logs for details)")

    # ===================
    # COMPLETION
    # ===================
    print("\n" + "=" * 70)
    print("[+] Unified Reporting Complete")
    print("=" * 70)

    print("\n[+] Generated Reports:")
    for report_path in report_paths:
        print(f"    {report_path}")

    if args.defectdojo and args.engagement_id:
        print("\n[+] DefectDojo:")
        print(f"    Engagement ID: {args.engagement_id}")
        print(f"    URL: {dd_client.base_url}/engagement/{args.engagement_id}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
