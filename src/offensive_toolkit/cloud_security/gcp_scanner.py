"""
GCP Cloud Security Scanner

Comprehensive GCP security assessment tool for authorized testing.
Identifies GCP IAM misconfigurations, GCS bucket exposures, firewall issues,
and other common GCP security weaknesses.

MITRE ATT&CK Mapping:
- T1580: Cloud Infrastructure Discovery
- T1526: Cloud Service Discovery
- T1087.004: Account Discovery - Cloud Account
- T1069.003: Permission Groups Discovery - Cloud Groups
- T1078.004: Valid Accounts - Cloud Accounts
- T1552.005: Unsecured Credentials - Cloud Instance Metadata API

Author: David Dashti
License: Educational/Research Use Only
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from google.api_core import exceptions as gcp_exceptions
    from google.auth import default as google_auth_default
    from google.cloud import compute_v1, storage
    from google.oauth2 import service_account
except ImportError:
    raise ImportError(
        "GCP SDK not installed. Run: pip install google-cloud-storage google-cloud-compute google-auth"
    )

# Configure logging
logger = logging.getLogger(__name__)


class GCPScanner:
    """
    GCP Security Scanner for identifying misconfigurations and security issues.

    Features:
    - IAM policy analysis and overly permissive roles
    - GCS bucket public exposure detection
    - Firewall rules allowing unrestricted access
    - Public compute instances
    - Service account key management
    - Disk encryption validation
    """

    def __init__(self, project_id: str | None = None, credentials_file: str | None = None):
        """
        Initialize GCP scanner with credentials.

        Args:
            project_id: GCP project ID (auto-detect if None)
            credentials_file: Path to service account JSON file (uses ADC if None)
        """
        self.project_id = project_id
        self.findings = {
            "scan_metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "scanner": "GCPScanner",
                "project_id": project_id,
            },
            "storage": [],
            "compute": [],
            "iam": [],
            "network": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

        # Initialize GCP credentials
        try:
            if credentials_file:
                credentials = service_account.Credentials.from_service_account_file(
                    credentials_file
                )
                logger.info(f"[+] Using service account credentials from {credentials_file}")
            else:
                credentials, default_project = google_auth_default()
                if not self.project_id and default_project:
                    self.project_id = default_project
                logger.info("[+] Using Application Default Credentials")

            if not self.project_id:
                raise ValueError("Project ID not provided and could not be auto-detected")

            self.findings["scan_metadata"]["project_id"] = self.project_id

            # Initialize clients
            self.storage_client = storage.Client(project=self.project_id, credentials=credentials)
            self.compute_client = compute_v1.InstancesClient(credentials=credentials)
            self.firewall_client = compute_v1.FirewallsClient(credentials=credentials)
            self.disk_client = compute_v1.DisksClient(credentials=credentials)

            logger.info(f"[+] GCP scanner initialized for project {self.project_id}")

        except gcp_exceptions.GoogleAPIError as e:
            logger.error(f"[-] GCP API error during initialization: {e}")
            raise
        except Exception as e:
            logger.error(f"[-] Error initializing GCP scanner: {e}")
            raise

    def _add_finding(self, category: str, finding: dict[str, Any]) -> None:
        """Add finding and update severity counts."""
        self.findings[category].append(finding)
        severity = finding.get("severity", "info")
        self.findings["summary"][severity] = self.findings["summary"].get(severity, 0) + 1

    def scan_gcs_buckets(self) -> None:
        """
        Scan GCS buckets for public exposure and misconfigurations.

        Checks:
        - Publicly accessible buckets (allUsers, allAuthenticatedUsers)
        - Buckets without uniform bucket-level access
        - Buckets without encryption
        - Buckets without versioning
        - Buckets without logging
        """
        logger.info("[*] Scanning GCS buckets...")

        try:
            buckets = list(self.storage_client.list_buckets())

            for bucket in buckets:
                bucket_name = bucket.name

                # Reload to get full metadata
                bucket.reload()

                # Check IAM policy for public access
                policy = bucket.get_iam_policy()
                for binding in policy.bindings:
                    if (
                        "allUsers" in binding["members"]
                        or "allAuthenticatedUsers" in binding["members"]
                    ):
                        self._add_finding(
                            "storage",
                            {
                                "type": "gcs_public_access",
                                "bucket": bucket_name,
                                "role": binding["role"],
                                "members": binding["members"],
                                "description": f"GCS bucket {bucket_name} allows public access",
                                "severity": "critical",
                                "recommendation": "Remove allUsers and allAuthenticatedUsers from bucket IAM",
                                "mitre": "T1530",
                            },
                        )

                # Check uniform bucket-level access
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    self._add_finding(
                        "storage",
                        {
                            "type": "gcs_no_uniform_access",
                            "bucket": bucket_name,
                            "description": f"GCS bucket {bucket_name} does not have uniform bucket-level access enabled",
                            "severity": "medium",
                            "recommendation": "Enable uniform bucket-level access for consistent IAM policies",
                            "mitre": "T1530",
                        },
                    )

                # Check versioning
                if not bucket.versioning_enabled:
                    self._add_finding(
                        "storage",
                        {
                            "type": "gcs_versioning_disabled",
                            "bucket": bucket_name,
                            "description": f"GCS bucket {bucket_name} does not have versioning enabled",
                            "severity": "medium",
                            "recommendation": "Enable object versioning for data protection",
                            "mitre": "T1530",
                        },
                    )

                # Check encryption (default encryption uses Google-managed keys)
                if bucket.default_kms_key_name:
                    # Has customer-managed encryption key (CMEK) - good
                    pass
                else:
                    self._add_finding(
                        "storage",
                        {
                            "type": "gcs_no_cmek",
                            "bucket": bucket_name,
                            "description": f"GCS bucket {bucket_name} uses Google-managed encryption keys instead of CMEK",
                            "severity": "low",
                            "recommendation": "Consider using customer-managed encryption keys for sensitive data",
                            "mitre": "T1530",
                        },
                    )

                # Check logging
                if not bucket.logging:
                    self._add_finding(
                        "storage",
                        {
                            "type": "gcs_no_logging",
                            "bucket": bucket_name,
                            "description": f"GCS bucket {bucket_name} does not have access logging enabled",
                            "severity": "medium",
                            "recommendation": "Enable access logging for audit trails",
                            "mitre": "T1562.008",
                        },
                    )

            logger.info(f"[+] GCS scan complete: {len(buckets)} buckets analyzed")

        except gcp_exceptions.GoogleAPIError as e:
            logger.error(f"[-] Error scanning GCS buckets: {e}")

    def scan_firewall_rules(self) -> None:
        """
        Scan VPC firewall rules for overly permissive configurations.

        Checks:
        - Rules allowing 0.0.0.0/0 on risky ports
        - Rules allowing all protocols
        - Rules allowing all ports
        - Disabled firewall rules (informational)
        """
        logger.info("[*] Scanning VPC firewall rules...")

        try:
            request = compute_v1.ListFirewallsRequest(project=self.project_id)
            firewalls = list(self.firewall_client.list(request=request))

            risky_ports = [22, 3389, 3306, 5432, 1433, 5984, 6379, 7000, 8080, 8888, 9200, 27017]

            for firewall in firewalls:
                firewall_name = firewall.name

                # Only check ALLOW rules
                if firewall.direction == "INGRESS" and len(firewall.allowed) > 0:
                    # Check source ranges
                    has_public_source = False
                    if firewall.source_ranges:
                        for source_range in firewall.source_ranges:
                            if source_range in ["0.0.0.0/0", "*"]:
                                has_public_source = True
                                break

                    if has_public_source:
                        for allowed_rule in firewall.allowed:
                            protocol = allowed_rule.ip_protocol

                            # Check for all protocols
                            if protocol == "all":
                                self._add_finding(
                                    "network",
                                    {
                                        "type": "gcp_firewall_all_protocols",
                                        "firewall_name": firewall_name,
                                        "description": f"Firewall rule {firewall_name} allows all protocols from 0.0.0.0/0",
                                        "severity": "critical",
                                        "recommendation": "Restrict to specific protocols and source ranges",
                                        "mitre": "T1046",
                                    },
                                )
                                continue

                            # Check ports
                            ports = allowed_rule.ports if allowed_rule.ports else ["all"]

                            for port_range in ports:
                                if port_range == "all":
                                    self._add_finding(
                                        "network",
                                        {
                                            "type": "gcp_firewall_all_ports",
                                            "firewall_name": firewall_name,
                                            "protocol": protocol,
                                            "description": f"Firewall rule {firewall_name} allows all ports from 0.0.0.0/0",
                                            "severity": "critical",
                                            "recommendation": "Restrict to specific ports and source ranges",
                                            "mitre": "T1046",
                                        },
                                    )
                                else:
                                    # Parse port range
                                    if "-" in port_range:
                                        start_port, end_port = map(int, port_range.split("-"))
                                        port_list = range(start_port, end_port + 1)
                                    else:
                                        port_list = [int(port_range)]

                                    # Check for risky ports
                                    risky_found = [p for p in port_list if p in risky_ports]
                                    if risky_found:
                                        self._add_finding(
                                            "network",
                                            {
                                                "type": "gcp_firewall_risky_port",
                                                "firewall_name": firewall_name,
                                                "protocol": protocol,
                                                "ports": risky_found,
                                                "description": f"Firewall rule {firewall_name} allows risky ports {risky_found} from 0.0.0.0/0",
                                                "severity": "critical",
                                                "recommendation": "Restrict access to specific source ranges",
                                                "mitre": "T1046",
                                            },
                                        )
                                    else:
                                        self._add_finding(
                                            "network",
                                            {
                                                "type": "gcp_firewall_public_access",
                                                "firewall_name": firewall_name,
                                                "protocol": protocol,
                                                "ports": port_range,
                                                "description": f"Firewall rule {firewall_name} allows public access on {protocol}/{port_range}",
                                                "severity": "high",
                                                "recommendation": "Restrict source ranges to known IPs",
                                                "mitre": "T1046",
                                            },
                                        )

                # Check if rule is disabled
                if firewall.disabled:
                    self._add_finding(
                        "network",
                        {
                            "type": "gcp_firewall_disabled",
                            "firewall_name": firewall_name,
                            "description": f"Firewall rule {firewall_name} is disabled",
                            "severity": "info",
                            "recommendation": "Review and delete unused firewall rules",
                            "mitre": "T1562",
                        },
                    )

            logger.info(f"[+] Firewall scan complete: {len(firewalls)} rules analyzed")

        except gcp_exceptions.GoogleAPIError as e:
            logger.error(f"[-] Error scanning firewall rules: {e}")

    def scan_compute_instances(self) -> None:
        """
        Scan Compute Engine instances for security issues.

        Checks:
        - Instances with public IP addresses
        - Instances with full cloud-api access scope
        - Instances without Shielded VM features
        - Instances with default service account
        """
        logger.info("[*] Scanning Compute Engine instances...")

        try:
            # List all zones
            zones_client = compute_v1.ZonesClient()
            zones_request = compute_v1.ListZonesRequest(project=self.project_id)
            zones = list(zones_client.list(request=zones_request))

            for zone in zones:
                zone_name = zone.name

                # List instances in zone
                request = compute_v1.ListInstancesRequest(project=self.project_id, zone=zone_name)
                instances = list(self.compute_client.list(request=request))

                for instance in instances:
                    instance_name = instance.name

                    # Check for public IP
                    has_public_ip = False
                    for network_interface in instance.network_interfaces:
                        if network_interface.access_configs:
                            for access_config in network_interface.access_configs:
                                if access_config.nat_i_p:
                                    has_public_ip = True
                                    self._add_finding(
                                        "compute",
                                        {
                                            "type": "gcp_instance_public_ip",
                                            "instance_name": instance_name,
                                            "zone": zone_name,
                                            "public_ip": access_config.nat_i_p,
                                            "description": f"Instance {instance_name} has a public IP address",
                                            "severity": "medium",
                                            "recommendation": "Use Cloud IAP or VPN for access",
                                            "mitre": "T1580",
                                        },
                                    )

                    # Check service account scopes
                    for service_account in instance.service_accounts:
                        # Check for default service account
                        if "compute@developer.gserviceaccount.com" in service_account.email:
                            self._add_finding(
                                "compute",
                                {
                                    "type": "gcp_instance_default_sa",
                                    "instance_name": instance_name,
                                    "zone": zone_name,
                                    "description": f"Instance {instance_name} uses default Compute Engine service account",
                                    "severity": "medium",
                                    "recommendation": "Use custom service account with minimal permissions",
                                    "mitre": "T1078.004",
                                },
                            )

                        # Check for overly broad scopes
                        if (
                            "https://www.googleapis.com/auth/cloud-platform"
                            in service_account.scopes
                        ):
                            self._add_finding(
                                "compute",
                                {
                                    "type": "gcp_instance_full_api_access",
                                    "instance_name": instance_name,
                                    "zone": zone_name,
                                    "service_account": service_account.email,
                                    "description": f"Instance {instance_name} has full cloud-api access scope",
                                    "severity": "high",
                                    "recommendation": "Use granular OAuth scopes instead of cloud-platform",
                                    "mitre": "T1078.004",
                                },
                            )

                    # Check Shielded VM features
                    if not instance.shielded_instance_config:
                        self._add_finding(
                            "compute",
                            {
                                "type": "gcp_instance_no_shielded_vm",
                                "instance_name": instance_name,
                                "zone": zone_name,
                                "description": f"Instance {instance_name} does not have Shielded VM enabled",
                                "severity": "medium",
                                "recommendation": "Enable Shielded VM for enhanced security",
                                "mitre": "T1542",
                            },
                        )

            logger.info("[+] Compute instance scan complete")

        except gcp_exceptions.GoogleAPIError as e:
            logger.error(f"[-] Error scanning compute instances: {e}")

    def scan_disks(self) -> None:
        """
        Scan persistent disks for encryption configuration.

        Checks:
        - Disks without customer-managed encryption keys (CMEK)
        """
        logger.info("[*] Scanning persistent disks...")

        try:
            # List all zones
            zones_client = compute_v1.ZonesClient()
            zones_request = compute_v1.ListZonesRequest(project=self.project_id)
            zones = list(zones_client.list(request=zones_request))

            for zone in zones:
                zone_name = zone.name

                # List disks in zone
                request = compute_v1.ListDisksRequest(project=self.project_id, zone=zone_name)
                disks = list(self.disk_client.list(request=request))

                for disk in disks:
                    disk_name = disk.name

                    # Check for CMEK
                    if not disk.disk_encryption_key or not disk.disk_encryption_key.kms_key_name:
                        self._add_finding(
                            "compute",
                            {
                                "type": "gcp_disk_no_cmek",
                                "disk_name": disk_name,
                                "zone": zone_name,
                                "description": f"Persistent disk {disk_name} uses Google-managed encryption instead of CMEK",
                                "severity": "low",
                                "recommendation": "Consider using customer-managed encryption keys for sensitive data",
                                "mitre": "T1530",
                            },
                        )

            logger.info("[+] Disk scan complete")

        except gcp_exceptions.GoogleAPIError as e:
            logger.error(f"[-] Error scanning disks: {e}")

    def scan_all(self) -> dict[str, Any]:
        """
        Run all GCP security scans.

        Returns:
            Dict containing all scan findings
        """
        logger.info("[!] Starting comprehensive GCP security scan...")
        logger.info(f"[!] Project ID: {self.project_id}")

        self.scan_gcs_buckets()
        self.scan_firewall_rules()
        self.scan_compute_instances()
        self.scan_disks()

        logger.info("[+] GCP security scan complete!")
        logger.info(
            f"[+] Findings: Critical={self.findings['summary']['critical']}, "
            f"High={self.findings['summary']['high']}, "
            f"Medium={self.findings['summary']['medium']}, "
            f"Low={self.findings['summary']['low']}"
        )

        return self.findings

    def save_results(self, output_file: Path) -> None:
        """Save scan results to JSON file."""
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            json.dump(self.findings, f, indent=2)

        logger.info(f"[+] Results saved to {output_file}")


def main():
    """CLI entry point for GCP scanner."""
    import argparse

    parser = argparse.ArgumentParser(
        description="GCP Cloud Security Scanner - Identify misconfigurations and security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with default project
  python gcp_scanner.py --scan-all --output gcp_findings.json

  # Scan specific project
  python gcp_scanner.py --project my-project-id --scan-all

  # Use service account credentials
  python gcp_scanner.py --credentials /path/to/sa.json --scan-all

  # Scan specific checks only
  python gcp_scanner.py --scan storage network --output results.json

MITRE ATT&CK Mapping:
  T1580: Cloud Infrastructure Discovery
  T1526: Cloud Service Discovery
  T1087.004: Account Discovery - Cloud Account
  T1530: Data from Cloud Storage Object
  T1046: Network Service Scanning
        """,
    )

    parser.add_argument("--project", help="GCP project ID")
    parser.add_argument("--credentials", help="Path to service account JSON file")
    parser.add_argument(
        "--scan",
        nargs="+",
        choices=["storage", "compute", "network", "iam"],
        help="Specific scans to run",
    )
    parser.add_argument("--scan-all", action="store_true", help="Run all scans")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/gcp_scan.json"),
        help="Output file path (default: output/gcp_scan.json)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(message)s")

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║           GCP Cloud Security Scanner v1.0                 ║
    ║           Authorized Security Testing Only                ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    try:
        scanner = GCPScanner(project_id=args.project, credentials_file=args.credentials)

        if args.scan_all:
            scanner.scan_all()
        elif args.scan:
            if "storage" in args.scan:
                scanner.scan_gcs_buckets()
            if "compute" in args.scan:
                scanner.scan_compute_instances()
                scanner.scan_disks()
            if "network" in args.scan:
                scanner.scan_firewall_rules()
        else:
            print("[-] Please specify --scan-all or --scan with specific checks")
            return 1

        scanner.save_results(args.output)

        return 0

    except Exception as e:
        logger.error(f"[-] Error: {e}")
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
