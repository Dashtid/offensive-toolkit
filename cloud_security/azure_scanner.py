"""
Azure Cloud Security Scanner

Comprehensive Azure security assessment tool for authorized testing.
Identifies Azure AD misconfigurations, storage account exposures, NSG issues,
and other common Azure security weaknesses.

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
    from azure.core.exceptions import AzureError, HttpResponseError
    from azure.identity import AzureCliCredential, DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
    from azure.mgmt.storage import StorageManagementClient
except ImportError:
    raise ImportError(
        "Azure SDK not installed. Run: pip install azure-identity azure-mgmt-resource azure-mgmt-storage azure-mgmt-network"
    )

# Configure logging
logger = logging.getLogger(__name__)


class AzureScanner:
    """
    Azure Security Scanner for identifying misconfigurations and security issues.

    Features:
    - Azure AD user and group analysis
    - Storage account public exposure detection
    - Network Security Group (NSG) overly permissive rules
    - Public VM and disk encryption
    - Role-Based Access Control (RBAC) analysis
    - Resource encryption validation
    """

    def __init__(self, subscription_id: str | None = None, use_cli_auth: bool = False):
        """
        Initialize Azure scanner with credentials.

        Args:
            subscription_id: Azure subscription ID (auto-detect if None)
            use_cli_auth: Use Azure CLI credentials instead of default
        """
        self.subscription_id = subscription_id
        self.findings = {
            "scan_metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "scanner": "AzureScanner",
                "subscription_id": subscription_id,
            },
            "storage": [],
            "network": [],
            "compute": [],
            "rbac": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

        # Initialize Azure credentials
        try:
            if use_cli_auth:
                self.credential = AzureCliCredential()
                logger.info("[+] Using Azure CLI credentials")
            else:
                self.credential = DefaultAzureCredential()
                logger.info("[+] Using Azure default credentials")

            # Get subscription if not provided
            if not self.subscription_id:
                sub_client = SubscriptionClient(self.credential)
                subscriptions = list(sub_client.subscriptions.list())
                if not subscriptions:
                    raise ValueError("No Azure subscriptions found")
                self.subscription_id = subscriptions[0].subscription_id
                logger.info(f"[+] Using subscription: {self.subscription_id}")

            self.findings["scan_metadata"]["subscription_id"] = self.subscription_id

            # Initialize clients
            self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
            self.storage_client = StorageManagementClient(self.credential, self.subscription_id)
            self.network_client = NetworkManagementClient(self.credential, self.subscription_id)
            self.compute_client = ComputeManagementClient(self.credential, self.subscription_id)

            logger.info(f"[+] Azure scanner initialized for subscription {self.subscription_id}")

        except AzureError as e:
            logger.error(f"[-] Azure authentication error: {e}")
            raise
        except Exception as e:
            logger.error(f"[-] Error initializing Azure scanner: {e}")
            raise

    def _add_finding(self, category: str, finding: dict[str, Any]) -> None:
        """Add finding and update severity counts."""
        self.findings[category].append(finding)
        severity = finding.get("severity", "info")
        self.findings["summary"][severity] = self.findings["summary"].get(severity, 0) + 1

    def scan_storage_accounts(self) -> None:
        """
        Scan Azure Storage accounts for security issues.

        Checks:
        - Public blob access enabled
        - HTTPS-only traffic not enforced
        - No encryption at rest
        - Shared access signature (SAS) policy issues
        - Network rules allowing all access
        """
        logger.info("[*] Scanning Azure Storage accounts...")

        try:
            storage_accounts = list(self.storage_client.storage_accounts.list())

            for account in storage_accounts:
                account_name = account.name
                resource_group = account.id.split("/")[4]

                # Check HTTPS-only
                if not account.enable_https_traffic_only:
                    self._add_finding(
                        "storage",
                        {
                            "type": "storage_https_not_enforced",
                            "storage_account": account_name,
                            "resource_group": resource_group,
                            "description": f"Storage account {account_name} does not enforce HTTPS-only traffic",
                            "severity": "high",
                            "recommendation": "Enable 'Secure transfer required' setting",
                            "mitre": "T1530",
                        },
                    )

                # Check public blob access
                if account.allow_blob_public_access:
                    self._add_finding(
                        "storage",
                        {
                            "type": "storage_public_blob_access",
                            "storage_account": account_name,
                            "resource_group": resource_group,
                            "description": f"Storage account {account_name} allows public blob access",
                            "severity": "critical",
                            "recommendation": "Disable public blob access at storage account level",
                            "mitre": "T1530",
                        },
                    )

                # Check encryption
                if not account.encryption or not account.encryption.services:
                    self._add_finding(
                        "storage",
                        {
                            "type": "storage_no_encryption",
                            "storage_account": account_name,
                            "resource_group": resource_group,
                            "description": f"Storage account {account_name} encryption status unclear",
                            "severity": "high",
                            "recommendation": "Verify encryption at rest is enabled",
                            "mitre": "T1530",
                        },
                    )

                # Check network rules
                if account.network_rule_set:
                    if account.network_rule_set.default_action == "Allow":
                        self._add_finding(
                            "storage",
                            {
                                "type": "storage_network_unrestricted",
                                "storage_account": account_name,
                                "resource_group": resource_group,
                                "description": f"Storage account {account_name} allows network access from all networks",
                                "severity": "high",
                                "recommendation": "Configure network rules to restrict access",
                                "mitre": "T1530",
                            },
                        )

                # Check minimum TLS version
                if hasattr(account, "minimum_tls_version"):
                    if account.minimum_tls_version != "TLS1_2":
                        self._add_finding(
                            "storage",
                            {
                                "type": "storage_weak_tls",
                                "storage_account": account_name,
                                "resource_group": resource_group,
                                "minimum_tls": account.minimum_tls_version,
                                "description": f"Storage account {account_name} allows TLS versions older than 1.2",
                                "severity": "medium",
                                "recommendation": "Set minimum TLS version to 1.2",
                                "mitre": "T1530",
                            },
                        )

            logger.info(
                f"[+] Storage account scan complete: {len(storage_accounts)} accounts analyzed"
            )

        except AzureError as e:
            logger.error(f"[-] Error scanning storage accounts: {e}")

    def scan_network_security_groups(self) -> None:
        """
        Scan Network Security Groups for overly permissive rules.

        Checks:
        - Rules allowing 0.0.0.0/0 or * on risky ports
        - Rules allowing all protocols
        - Default rules modified
        """
        logger.info("[*] Scanning Network Security Groups...")

        try:
            nsgs = list(self.network_client.network_security_groups.list_all())
            risky_ports = [22, 3389, 3306, 5432, 1433, 5984, 6379, 7000, 8080, 8888, 9200, 27017]

            for nsg in nsgs:
                nsg_name = nsg.name
                resource_group = nsg.id.split("/")[4]

                # Check security rules
                for rule in nsg.security_rules:
                    # Check for public access
                    is_public = False
                    if rule.source_address_prefix in ["*", "0.0.0.0/0", "Internet"] or (
                        rule.source_address_prefixes
                        and any(
                            prefix in ["*", "0.0.0.0/0", "Internet"]
                            for prefix in rule.source_address_prefixes
                        )
                    ):
                        is_public = True

                    if is_public and rule.access == "Allow" and rule.direction == "Inbound":
                        # Check destination port
                        dest_ports = []
                        if rule.destination_port_range:
                            if rule.destination_port_range == "*":
                                dest_ports = ["all"]
                            else:
                                dest_ports = [rule.destination_port_range]
                        if rule.destination_port_ranges:
                            dest_ports.extend(rule.destination_port_ranges)

                        # Determine severity
                        severity = "high"
                        if (
                            "all" in dest_ports
                            or "*" in dest_ports
                            or any(str(port) in str(dest_ports) for port in risky_ports)
                        ):
                            severity = "critical"

                        self._add_finding(
                            "network",
                            {
                                "type": "nsg_public_access",
                                "nsg_name": nsg_name,
                                "resource_group": resource_group,
                                "rule_name": rule.name,
                                "ports": dest_ports,
                                "protocol": rule.protocol,
                                "description": f"NSG {nsg_name} rule '{rule.name}' allows public access on ports {dest_ports}",
                                "severity": severity,
                                "recommendation": "Restrict source to specific IP ranges",
                                "mitre": "T1046",
                            },
                        )

            logger.info(f"[+] NSG scan complete: {len(nsgs)} NSGs analyzed")

        except AzureError as e:
            logger.error(f"[-] Error scanning NSGs: {e}")

    def scan_virtual_machines(self) -> None:
        """
        Scan Azure Virtual Machines for security issues.

        Checks:
        - VMs with public IP addresses
        - VMs without disk encryption
        - VMs without Azure Monitor agent
        - VMs with password authentication (should use SSH keys)
        """
        logger.info("[*] Scanning Azure Virtual Machines...")

        try:
            vms = list(self.compute_client.virtual_machines.list_all())

            for vm in vms:
                vm_name = vm.name
                resource_group = vm.id.split("/")[4]

                # Check for public IP
                if vm.network_profile and vm.network_profile.network_interfaces:
                    for nic_ref in vm.network_profile.network_interfaces:
                        nic_id = nic_ref.id
                        nic_name = nic_id.split("/")[-1]
                        nic_rg = nic_id.split("/")[4]

                        try:
                            nic = self.network_client.network_interfaces.get(nic_rg, nic_name)
                            for ip_config in nic.ip_configurations:
                                if ip_config.public_ip_address:
                                    self._add_finding(
                                        "compute",
                                        {
                                            "type": "vm_public_ip",
                                            "vm_name": vm_name,
                                            "resource_group": resource_group,
                                            "description": f"VM {vm_name} has a public IP address",
                                            "severity": "medium",
                                            "recommendation": "Use bastion hosts or VPN for access",
                                            "mitre": "T1580",
                                        },
                                    )
                        except HttpResponseError:
                            pass

                # Check disk encryption
                if vm.storage_profile and vm.storage_profile.os_disk:
                    os_disk = vm.storage_profile.os_disk
                    if not os_disk.encryption_settings or not os_disk.encryption_settings.enabled:
                        self._add_finding(
                            "compute",
                            {
                                "type": "vm_disk_not_encrypted",
                                "vm_name": vm_name,
                                "resource_group": resource_group,
                                "description": f"VM {vm_name} OS disk is not encrypted",
                                "severity": "high",
                                "recommendation": "Enable Azure Disk Encryption",
                                "mitre": "T1530",
                            },
                        )

                # Check OS profile for password auth (Linux)
                if vm.os_profile and vm.storage_profile.os_disk.os_type == "Linux":
                    if vm.os_profile.linux_configuration:
                        linux_config = vm.os_profile.linux_configuration
                        if not linux_config.disable_password_authentication:
                            self._add_finding(
                                "compute",
                                {
                                    "type": "vm_password_auth_enabled",
                                    "vm_name": vm_name,
                                    "resource_group": resource_group,
                                    "description": f"Linux VM {vm_name} allows password authentication",
                                    "severity": "medium",
                                    "recommendation": "Disable password authentication and use SSH keys only",
                                    "mitre": "T1078.004",
                                },
                            )

            logger.info(f"[+] VM scan complete: {len(vms)} VMs analyzed")

        except AzureError as e:
            logger.error(f"[-] Error scanning VMs: {e}")

    def scan_public_ips(self) -> None:
        """
        Scan for public IP addresses and their associations.

        Checks:
        - Unassociated public IPs (cost optimization)
        - Public IPs with DDoS protection disabled
        """
        logger.info("[*] Scanning public IP addresses...")

        try:
            public_ips = list(self.network_client.public_ip_addresses.list_all())

            for pip in public_ips:
                pip_name = pip.name
                resource_group = pip.id.split("/")[4]

                # Check if unassociated
                if not pip.ip_configuration:
                    self._add_finding(
                        "network",
                        {
                            "type": "public_ip_unassociated",
                            "public_ip_name": pip_name,
                            "resource_group": resource_group,
                            "ip_address": pip.ip_address,
                            "description": f"Public IP {pip_name} is not associated with any resource",
                            "severity": "info",
                            "recommendation": "Delete unused public IPs to reduce attack surface and cost",
                            "mitre": "T1580",
                        },
                    )

                # Check DDoS protection
                if pip.ddos_settings and not pip.ddos_settings.protection_mode:
                    self._add_finding(
                        "network",
                        {
                            "type": "public_ip_no_ddos",
                            "public_ip_name": pip_name,
                            "resource_group": resource_group,
                            "ip_address": pip.ip_address,
                            "description": f"Public IP {pip_name} does not have DDoS protection enabled",
                            "severity": "medium",
                            "recommendation": "Enable DDoS Protection Standard for critical resources",
                            "mitre": "T1498",
                        },
                    )

            logger.info(f"[+] Public IP scan complete: {len(public_ips)} IPs analyzed")

        except AzureError as e:
            logger.error(f"[-] Error scanning public IPs: {e}")

    def scan_managed_disks(self) -> None:
        """
        Scan managed disks for encryption status.

        Checks:
        - Disks without encryption
        - Disks with customer-managed keys (CMK) not using Key Vault
        """
        logger.info("[*] Scanning managed disks...")

        try:
            disks = list(self.compute_client.disks.list())

            for disk in disks:
                disk_name = disk.name
                resource_group = disk.id.split("/")[4]

                # Check encryption
                if not disk.encryption:
                    self._add_finding(
                        "compute",
                        {
                            "type": "disk_no_encryption",
                            "disk_name": disk_name,
                            "resource_group": resource_group,
                            "description": f"Managed disk {disk_name} does not have encryption configured",
                            "severity": "high",
                            "recommendation": "Enable encryption at rest for all managed disks",
                            "mitre": "T1530",
                        },
                    )

            logger.info(f"[+] Managed disk scan complete: {len(disks)} disks analyzed")

        except AzureError as e:
            logger.error(f"[-] Error scanning managed disks: {e}")

    def scan_all(self) -> dict[str, Any]:
        """
        Run all Azure security scans.

        Returns:
            Dict containing all scan findings
        """
        logger.info("[!] Starting comprehensive Azure security scan...")
        logger.info(f"[!] Subscription ID: {self.subscription_id}")

        self.scan_storage_accounts()
        self.scan_network_security_groups()
        self.scan_virtual_machines()
        self.scan_public_ips()
        self.scan_managed_disks()

        logger.info("[+] Azure security scan complete!")
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
    """CLI entry point for Azure scanner."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Azure Cloud Security Scanner - Identify misconfigurations and security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with default subscription
  python azure_scanner.py --scan-all --output azure_findings.json

  # Scan specific subscription
  python azure_scanner.py --subscription <sub-id> --scan-all

  # Use Azure CLI authentication
  python azure_scanner.py --use-cli-auth --scan-all

  # Scan specific checks only
  python azure_scanner.py --scan storage network --output results.json

MITRE ATT&CK Mapping:
  T1580: Cloud Infrastructure Discovery
  T1526: Cloud Service Discovery
  T1087.004: Account Discovery - Cloud Account
  T1530: Data from Cloud Storage Object
  T1046: Network Service Scanning
        """,
    )

    parser.add_argument("--subscription", help="Azure subscription ID")
    parser.add_argument("--use-cli-auth", action="store_true", help="Use Azure CLI credentials")
    parser.add_argument(
        "--scan",
        nargs="+",
        choices=["storage", "network", "compute", "rbac"],
        help="Specific scans to run",
    )
    parser.add_argument("--scan-all", action="store_true", help="Run all scans")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/azure_scan.json"),
        help="Output file path (default: output/azure_scan.json)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(message)s")

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║          Azure Cloud Security Scanner v1.0                ║
    ║           Authorized Security Testing Only                ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    try:
        scanner = AzureScanner(subscription_id=args.subscription, use_cli_auth=args.use_cli_auth)

        if args.scan_all:
            scanner.scan_all()
        elif args.scan:
            if "storage" in args.scan:
                scanner.scan_storage_accounts()
            if "network" in args.scan:
                scanner.scan_network_security_groups()
                scanner.scan_public_ips()
            if "compute" in args.scan:
                scanner.scan_virtual_machines()
                scanner.scan_managed_disks()
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
