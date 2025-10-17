"""
Unified Multi-Cloud Security Scanner CLI

Comprehensive security assessment tool for AWS, Azure, and GCP.
Provides unified interface for scanning multiple cloud providers in parallel.

MITRE ATT&CK Mapping:
- T1580: Cloud Infrastructure Discovery
- T1526: Cloud Service Discovery
- T1087.004: Account Discovery - Cloud Account

Author: David Dashti
License: Educational/Research Use Only
"""

import argparse
import concurrent.futures
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from .aws_scanner import AWSScanner
from .azure_scanner import AzureScanner
from .gcp_scanner import GCPScanner

# Configure logging
logger = logging.getLogger(__name__)


class MultiCloudScanner:
    """
    Unified scanner for AWS, Azure, and GCP cloud security assessment.

    Features:
    - Parallel scanning of multiple cloud providers
    - Unified findings format
    - Aggregated security metrics
    - Cross-cloud comparison
    """

    def __init__(self):
        """Initialize multi-cloud scanner."""
        self.findings = {
            "scan_metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "scanner": "MultiCloudScanner",
                "clouds_scanned": [],
            },
            "aws": {},
            "azure": {},
            "gcp": {},
            "summary": {
                "total_critical": 0,
                "total_high": 0,
                "total_medium": 0,
                "total_low": 0,
                "total_info": 0,
                "by_cloud": {},
            },
        }

    def scan_aws(self, profile: str | None = None, region: str = "us-east-1") -> dict[str, Any]:
        """
        Scan AWS environment.

        Args:
            profile: AWS CLI profile name
            region: AWS region

        Returns:
            Dict containing AWS scan findings
        """
        logger.info("[*] Starting AWS scan...")
        try:
            scanner = AWSScanner(profile_name=profile, region=region)
            results = scanner.scan_all()
            self.findings["aws"] = results
            self.findings["scan_metadata"]["clouds_scanned"].append("aws")

            # Update summary
            self.findings["summary"]["by_cloud"]["aws"] = results["summary"]
            for severity in ["critical", "high", "medium", "low", "info"]:
                self.findings["summary"][f"total_{severity}"] += results["summary"][severity]

            logger.info("[+] AWS scan complete")
            return results
        except Exception as e:
            logger.error(f"[-] AWS scan failed: {e}")
            self.findings["aws"] = {"error": str(e)}
            return {}

    def scan_azure(
        self, subscription_id: str | None = None, use_cli_auth: bool = False
    ) -> dict[str, Any]:
        """
        Scan Azure environment.

        Args:
            subscription_id: Azure subscription ID
            use_cli_auth: Use Azure CLI authentication

        Returns:
            Dict containing Azure scan findings
        """
        logger.info("[*] Starting Azure scan...")
        try:
            scanner = AzureScanner(subscription_id=subscription_id, use_cli_auth=use_cli_auth)
            results = scanner.scan_all()
            self.findings["azure"] = results
            self.findings["scan_metadata"]["clouds_scanned"].append("azure")

            # Update summary
            self.findings["summary"]["by_cloud"]["azure"] = results["summary"]
            for severity in ["critical", "high", "medium", "low", "info"]:
                self.findings["summary"][f"total_{severity}"] += results["summary"][severity]

            logger.info("[+] Azure scan complete")
            return results
        except Exception as e:
            logger.error(f"[-] Azure scan failed: {e}")
            self.findings["azure"] = {"error": str(e)}
            return {}

    def scan_gcp(
        self, project_id: str | None = None, credentials_file: str | None = None
    ) -> dict[str, Any]:
        """
        Scan GCP environment.

        Args:
            project_id: GCP project ID
            credentials_file: Path to service account JSON

        Returns:
            Dict containing GCP scan findings
        """
        logger.info("[*] Starting GCP scan...")
        try:
            scanner = GCPScanner(project_id=project_id, credentials_file=credentials_file)
            results = scanner.scan_all()
            self.findings["gcp"] = results
            self.findings["scan_metadata"]["clouds_scanned"].append("gcp")

            # Update summary
            self.findings["summary"]["by_cloud"]["gcp"] = results["summary"]
            for severity in ["critical", "high", "medium", "low", "info"]:
                self.findings["summary"][f"total_{severity}"] += results["summary"][severity]

            logger.info("[+] GCP scan complete")
            return results
        except Exception as e:
            logger.error(f"[-] GCP scan failed: {e}")
            self.findings["gcp"] = {"error": str(e)}
            return {}

    def scan_all_parallel(
        self,
        aws_config: dict[str, Any] | None = None,
        azure_config: dict[str, Any] | None = None,
        gcp_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Scan all configured cloud providers in parallel.

        Args:
            aws_config: AWS configuration dict
            azure_config: Azure configuration dict
            gcp_config: GCP configuration dict

        Returns:
            Dict containing all scan findings
        """
        logger.info("[!] Starting multi-cloud security scan (parallel mode)...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}

            if aws_config:
                futures["aws"] = executor.submit(
                    self.scan_aws,
                    profile=aws_config.get("profile"),
                    region=aws_config.get("region", "us-east-1"),
                )

            if azure_config:
                futures["azure"] = executor.submit(
                    self.scan_azure,
                    subscription_id=azure_config.get("subscription_id"),
                    use_cli_auth=azure_config.get("use_cli_auth", False),
                )

            if gcp_config:
                futures["gcp"] = executor.submit(
                    self.scan_gcp,
                    project_id=gcp_config.get("project_id"),
                    credentials_file=gcp_config.get("credentials_file"),
                )

            # Wait for all scans to complete
            for cloud, future in futures.items():
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"[-] {cloud.upper()} scan error: {e}")

        logger.info("[+] Multi-cloud scan complete!")
        return self.findings

    def generate_summary_report(self) -> str:
        """
        Generate text summary report of findings.

        Returns:
            Formatted summary string
        """
        report_lines = []
        report_lines.append("\n" + "=" * 70)
        report_lines.append("MULTI-CLOUD SECURITY ASSESSMENT SUMMARY")
        report_lines.append("=" * 70)
        report_lines.append(f"\nScan Timestamp: {self.findings['scan_metadata']['timestamp']}")
        report_lines.append(
            f"Clouds Scanned: {', '.join(self.findings['scan_metadata']['clouds_scanned']).upper()}"
        )

        report_lines.append("\n" + "-" * 70)
        report_lines.append("AGGREGATE FINDINGS")
        report_lines.append("-" * 70)
        report_lines.append(
            f"  [CRITICAL]  {self.findings['summary']['total_critical']:3d} findings"
        )
        report_lines.append(f"  [HIGH]      {self.findings['summary']['total_high']:3d} findings")
        report_lines.append(f"  [MEDIUM]    {self.findings['summary']['total_medium']:3d} findings")
        report_lines.append(f"  [LOW]       {self.findings['summary']['total_low']:3d} findings")
        report_lines.append(f"  [INFO]      {self.findings['summary']['total_info']:3d} findings")

        total_findings = sum(
            [
                self.findings["summary"]["total_critical"],
                self.findings["summary"]["total_high"],
                self.findings["summary"]["total_medium"],
                self.findings["summary"]["total_low"],
                self.findings["summary"]["total_info"],
            ]
        )
        report_lines.append(f"\n  Total: {total_findings} findings across all clouds")

        # Per-cloud breakdown
        if self.findings["summary"]["by_cloud"]:
            report_lines.append("\n" + "-" * 70)
            report_lines.append("FINDINGS BY CLOUD PROVIDER")
            report_lines.append("-" * 70)

            for cloud, summary in self.findings["summary"]["by_cloud"].items():
                report_lines.append(f"\n{cloud.upper()}:")
                report_lines.append(f"  Critical: {summary['critical']}")
                report_lines.append(f"  High:     {summary['high']}")
                report_lines.append(f"  Medium:   {summary['medium']}")
                report_lines.append(f"  Low:      {summary['low']}")
                report_lines.append(f"  Info:     {summary['info']}")

        report_lines.append("\n" + "=" * 70)

        return "\n".join(report_lines)

    def save_results(self, output_file: Path) -> None:
        """Save scan results to JSON file."""
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            json.dump(self.findings, f, indent=2)

        logger.info(f"[+] Results saved to {output_file}")


def main():
    """CLI entry point for multi-cloud scanner."""
    parser = argparse.ArgumentParser(
        description="Multi-Cloud Security Scanner - Unified AWS, Azure, GCP assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan all clouds in parallel
  python cloud_cli.py --scan-all --output multi_cloud_findings.json

  # Scan specific clouds
  python cloud_cli.py --clouds aws azure --output findings.json

  # AWS-specific options
  python cloud_cli.py --clouds aws --aws-profile prod --aws-region us-west-2

  # Azure-specific options
  python cloud_cli.py --clouds azure --azure-subscription <sub-id> --use-azure-cli

  # GCP-specific options
  python cloud_cli.py --clouds gcp --gcp-project my-project --gcp-credentials /path/to/sa.json

  # Parallel multi-cloud scan
  python cloud_cli.py --scan-all --parallel --output comprehensive_scan.json

MITRE ATT&CK Mapping:
  T1580: Cloud Infrastructure Discovery
  T1526: Cloud Service Discovery
  T1087.004: Account Discovery - Cloud Account
        """,
    )

    # General options
    parser.add_argument(
        "--clouds", nargs="+", choices=["aws", "azure", "gcp"], help="Cloud providers to scan"
    )
    parser.add_argument("--scan-all", action="store_true", help="Scan all configured clouds")
    parser.add_argument("--parallel", action="store_true", help="Scan clouds in parallel (faster)")
    parser.add_argument(
        "--output", type=Path, default=Path("output/multi_cloud_scan.json"), help="Output file path"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # AWS options
    parser.add_argument("--aws-profile", help="AWS CLI profile name")
    parser.add_argument("--aws-region", default="us-east-1", help="AWS region")

    # Azure options
    parser.add_argument("--azure-subscription", help="Azure subscription ID")
    parser.add_argument("--use-azure-cli", action="store_true", help="Use Azure CLI authentication")

    # GCP options
    parser.add_argument("--gcp-project", help="GCP project ID")
    parser.add_argument("--gcp-credentials", help="Path to GCP service account JSON")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(message)s")

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║       Multi-Cloud Security Scanner v1.0                   ║
    ║       AWS + Azure + GCP Unified Assessment                ║
    ║       Authorized Security Testing Only                    ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    try:
        scanner = MultiCloudScanner()

        # Determine which clouds to scan
        clouds_to_scan = []
        if args.scan_all:
            # Attempt all clouds (failures will be graceful)
            clouds_to_scan = ["aws", "azure", "gcp"]
        elif args.clouds:
            clouds_to_scan = args.clouds
        else:
            print("[-] Please specify --scan-all or --clouds with specific providers")
            return 1

        # Prepare configurations
        aws_config = None
        azure_config = None
        gcp_config = None

        if "aws" in clouds_to_scan:
            aws_config = {"profile": args.aws_profile, "region": args.aws_region}

        if "azure" in clouds_to_scan:
            azure_config = {
                "subscription_id": args.azure_subscription,
                "use_cli_auth": args.use_azure_cli,
            }

        if "gcp" in clouds_to_scan:
            gcp_config = {"project_id": args.gcp_project, "credentials_file": args.gcp_credentials}

        # Execute scans
        if args.parallel:
            scanner.scan_all_parallel(
                aws_config=aws_config, azure_config=azure_config, gcp_config=gcp_config
            )
        else:
            # Sequential scanning
            if aws_config:
                scanner.scan_aws(profile=aws_config["profile"], region=aws_config["region"])
            if azure_config:
                scanner.scan_azure(
                    subscription_id=azure_config["subscription_id"],
                    use_cli_auth=azure_config["use_cli_auth"],
                )
            if gcp_config:
                scanner.scan_gcp(
                    project_id=gcp_config["project_id"],
                    credentials_file=gcp_config["credentials_file"],
                )

        # Generate and display summary
        summary = scanner.generate_summary_report()
        print(summary)

        # Save results
        scanner.save_results(args.output)

        # Exit with error code if critical findings exist
        if scanner.findings["summary"]["total_critical"] > 0:
            logger.warning(
                f"[!] {scanner.findings['summary']['total_critical']} CRITICAL findings detected!"
            )
            return 2

        return 0

    except Exception as e:
        logger.error(f"[-] Error: {e}")
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
