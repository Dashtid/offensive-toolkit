#!/usr/bin/env python3
"""
DefectDojo API Client - Vulnerability Management Integration

Integrates with DefectDojo for automated vulnerability tracking and reporting.

[!] REQUIRES: DefectDojo instance with API access
[!] AUTHENTICATION: Set DEFECTDOJO_API_KEY environment variable

Usage:
    python defectdojo_client.py --engagement-id 123 --scan-file output/sqli_*.json
    python defectdojo_client.py --create-engagement --product-id 1 --scan-dir output/

Examples:
    # Upload single scan to existing engagement
    python defectdojo_client.py --engagement-id 5 --scan-file output/port_scan.json

    # Create engagement and upload all scans
    python defectdojo_client.py --product-id 1 --create-engagement \\
        --name "Q4 2025 Pentest" --scan-dir output/

    # List products and engagements
    python defectdojo_client.py --list-products
    python defectdojo_client.py --list-engagements --product-id 1

Author: David Dashti
Date: 2025-10-15
"""

import argparse
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import requests

from utils.config import load_config
from utils.logger import get_logger

logger = get_logger(__name__)


class DefectDojoClient:
    """
    DefectDojo API client for vulnerability management integration.

    Supports creating engagements, uploading findings, and tracking remediation.
    """

    # Scan type mappings
    SCAN_TYPE_MAPPINGS = {
        "port_scan": "Nmap Scan",
        "dns": "Generic Findings Import",
        "subdomain": "Generic Findings Import",
        "whois": "Generic Findings Import",
        "sqli": "Generic Findings Import",
        "xss": "Generic Findings Import",
        "directory": "Generic Findings Import",
    }

    # Severity mappings
    SEVERITY_MAPPING = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
    }

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize DefectDojo client.

        Args:
            base_url: DefectDojo instance URL
            api_key: API authentication key
            config: Optional configuration dictionary
        """
        self.config = config or load_config()

        # Get DefectDojo URL from config or parameter
        self.base_url = (
            base_url
            or self.config.get("defectdojo", {}).get("url")
            or os.getenv("DEFECTDOJO_URL", "http://10.143.31.115")
        ).rstrip("/")

        # Get API key from environment or config
        self.api_key = (
            api_key
            or os.getenv("DEFECTDOJO_API_KEY")
            or self.config.get("defectdojo", {}).get("api_key")
        )

        if not self.api_key:
            logger.warning("No DefectDojo API key configured")

        self.api_url = f"{self.base_url}/api/v2"
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": f"Token {self.api_key}", "Content-Type": "application/json"}
        )

        logger.info(f"Initialized DefectDojo client for {self.base_url}")

    def _request(self, method: str, endpoint: str, **kwargs) -> dict[str, Any] | None:
        """
        Make authenticated API request.

        Args:
            method: HTTP method
            endpoint: API endpoint (without /api/v2 prefix)
            **kwargs: Additional request parameters

        Returns:
            Response data or None on error
        """
        url = f"{self.api_url}/{endpoint}"

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            if response.status_code == 204:  # No content
                return {}

            return response.json()

        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            logger.error(f"Response: {e.response.text if e.response else 'No response'}")
            return None
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None

    def test_connection(self) -> bool:
        """
        Test DefectDojo connection and authentication.

        Returns:
            True if connection successful
        """
        logger.info("Testing DefectDojo connection...")

        result = self._request("GET", "users/")

        if result:
            logger.info("DefectDojo connection successful")
            return True
        logger.error("DefectDojo connection failed")
        return False

    def list_products(self) -> list[dict[str, Any]]:
        """
        List all products.

        Returns:
            List of products
        """
        result = self._request("GET", "products/")

        if result and "results" in result:
            return result["results"]
        return []

    def get_product(self, product_id: int) -> dict[str, Any] | None:
        """
        Get product details.

        Args:
            product_id: Product ID

        Returns:
            Product data or None
        """
        return self._request("GET", f"products/{product_id}/")

    def create_product(
        self, name: str, description: str = "", product_type: int = 1
    ) -> dict[str, Any] | None:
        """
        Create new product.

        Args:
            name: Product name
            description: Product description
            product_type: Product type ID (default: 1)

        Returns:
            Created product data or None
        """
        data = {"name": name, "description": description, "prod_type": product_type}

        return self._request("POST", "products/", json=data)

    def list_engagements(self, product_id: int | None = None) -> list[dict[str, Any]]:
        """
        List engagements.

        Args:
            product_id: Filter by product ID

        Returns:
            List of engagements
        """
        params = {}
        if product_id:
            params["product"] = product_id

        result = self._request("GET", "engagements/", params=params)

        if result and "results" in result:
            return result["results"]
        return []

    def create_engagement(
        self,
        product_id: int,
        name: str,
        description: str = "",
        target_start: str | None = None,
        target_end: str | None = None,
        engagement_type: str = "Interactive",
        status: str = "In Progress",
    ) -> dict[str, Any] | None:
        """
        Create new engagement.

        Args:
            product_id: Product ID
            name: Engagement name
            description: Engagement description
            target_start: Start date (YYYY-MM-DD)
            target_end: End date (YYYY-MM-DD)
            engagement_type: Type (Interactive, CI/CD)
            status: Status (In Progress, Completed)

        Returns:
            Created engagement data or None
        """
        if not target_start:
            target_start = datetime.now().strftime("%Y-%m-%d")

        if not target_end:
            target_end = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")

        data = {
            "name": name,
            "description": description,
            "product": product_id,
            "target_start": target_start,
            "target_end": target_end,
            "engagement_type": engagement_type,
            "status": status,
        }

        return self._request("POST", "engagements/", json=data)

    def upload_scan(
        self,
        engagement_id: int,
        scan_file: Path,
        scan_type: str = "Generic Findings Import",
        scan_date: str | None = None,
        minimum_severity: str = "Info",
        active: bool = True,
        verified: bool = False,
    ) -> dict[str, Any] | None:
        """
        Upload scan results to engagement.

        Args:
            engagement_id: Engagement ID
            scan_file: Path to scan results file
            scan_type: DefectDojo scan type
            scan_date: Scan date (YYYY-MM-DD)
            minimum_severity: Minimum severity to import
            active: Mark findings as active
            verified: Mark findings as verified

        Returns:
            Upload result or None
        """
        if not scan_date:
            scan_date = datetime.now().strftime("%Y-%m-%d")

        # Read scan file
        try:
            with open(scan_file, "rb") as f:
                file_content = f.read()
        except Exception as e:
            logger.error(f"Error reading scan file: {e}")
            return None

        # Prepare multipart data
        files = {"file": (scan_file.name, file_content, "application/json")}

        data = {
            "engagement": engagement_id,
            "scan_type": scan_type,
            "scan_date": scan_date,
            "minimum_severity": minimum_severity,
            "active": str(active).lower(),
            "verified": str(verified).lower(),
        }

        # Remove Content-Type header for multipart request
        headers = self.session.headers.copy()
        headers.pop("Content-Type", None)

        url = f"{self.api_url}/import-scan/"

        try:
            response = requests.post(url, headers=headers, files=files, data=data)
            response.raise_for_status()

            logger.info(f"Uploaded scan {scan_file.name} to engagement {engagement_id}")
            return response.json() if response.content else {}

        except requests.exceptions.HTTPError as e:
            logger.error(f"Upload failed: {e}")
            logger.error(f"Response: {e.response.text if e.response else 'No response'}")
            return None
        except Exception as e:
            logger.error(f"Upload error: {e}")
            return None

    def import_findings(
        self, engagement_id: int, findings: list[dict[str, Any]], scan_date: str | None = None
    ) -> bool:
        """
        Import findings directly via API.

        Args:
            engagement_id: Engagement ID
            findings: List of finding dictionaries
            scan_date: Scan date

        Returns:
            True if successful
        """
        if not scan_date:
            scan_date = datetime.now().strftime("%Y-%m-%d")

        success_count = 0

        for finding in findings:
            # Map finding to DefectDojo format
            dd_finding = self._map_finding_to_defectdojo(finding, engagement_id, scan_date)

            if dd_finding:
                result = self._request("POST", "findings/", json=dd_finding)
                if result:
                    success_count += 1

        logger.info(f"Imported {success_count}/{len(findings)} findings")
        return success_count > 0

    def _map_finding_to_defectdojo(
        self, finding: dict[str, Any], engagement_id: int, scan_date: str
    ) -> dict[str, Any] | None:
        """
        Map toolkit finding to DefectDojo finding format.

        Args:
            finding: Toolkit finding
            engagement_id: Engagement ID
            scan_date: Scan date

        Returns:
            DefectDojo finding dictionary
        """
        # Extract finding details
        vuln_type = finding.get("type", "Unknown")
        severity = self.SEVERITY_MAPPING.get(finding.get("confidence", "low").lower(), "Low")

        title = f"{vuln_type} - {finding.get('parameter', 'Unknown')}"
        description = finding.get("evidence", "No description available")

        # Construct DefectDojo finding
        dd_finding = {
            "title": title,
            "description": description,
            "severity": severity,
            "date": scan_date,
            "active": True,
            "verified": False,
            "engagement": engagement_id,
            "test": None,  # Will be created automatically
        }

        # Add optional fields
        if "payload" in finding:
            dd_finding["description"] += f"\n\nPayload: {finding['payload']}"

        if "url" in finding:
            dd_finding["url"] = finding["url"]

        return dd_finding

    def _detect_scan_type_from_file(self, filename: str) -> str:
        """Detect DefectDojo scan type from filename."""
        filename_lower = filename.lower()

        for keyword, scan_type in self.SCAN_TYPE_MAPPINGS.items():
            if keyword in filename_lower:
                return scan_type

        return "Generic Findings Import"

    def bulk_upload(self, engagement_id: int, scan_dir: Path) -> dict[str, int]:
        """
        Upload all scans from directory.

        Args:
            engagement_id: Engagement ID
            scan_dir: Directory containing scan files

        Returns:
            Upload statistics
        """
        stats = {"success": 0, "failed": 0, "total": 0}

        scan_files = list(scan_dir.glob("*.json"))

        if not scan_files:
            logger.warning(f"No scan files found in {scan_dir}")
            return stats

        logger.info(f"Uploading {len(scan_files)} scans to engagement {engagement_id}")

        for scan_file in scan_files:
            stats["total"] += 1

            scan_type = self._detect_scan_type_from_file(scan_file.name)

            result = self.upload_scan(engagement_id, scan_file, scan_type=scan_type)

            if result:
                stats["success"] += 1
            else:
                stats["failed"] += 1

        return stats


def main() -> int:
    """Main entry point for command-line usage."""
    parser = argparse.ArgumentParser(
        description="DefectDojo API Client - Vulnerability Management Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Connection
    parser.add_argument("--url", help="DefectDojo URL (default: from config or env DEFECTDOJO_URL)")

    parser.add_argument("--api-key", help="API key (default: from env DEFECTDOJO_API_KEY)")

    parser.add_argument("--test-connection", action="store_true", help="Test connection and exit")

    # Listing
    parser.add_argument("--list-products", action="store_true", help="List all products")

    parser.add_argument("--list-engagements", action="store_true", help="List engagements")

    parser.add_argument("--product-id", type=int, help="Product ID")

    # Engagement creation
    parser.add_argument("--create-engagement", action="store_true", help="Create new engagement")

    parser.add_argument("--engagement-name", help="Engagement name")

    parser.add_argument("--engagement-id", type=int, help="Existing engagement ID for uploads")

    # Scan uploads
    parser.add_argument("--scan-file", type=Path, help="Single scan file to upload")

    parser.add_argument("--scan-dir", type=Path, help="Directory containing scan files to upload")

    parser.add_argument(
        "--scan-type", default="Generic Findings Import", help="DefectDojo scan type"
    )

    args = parser.parse_args()

    # Initialize client
    client = DefectDojoClient(base_url=args.url, api_key=args.api_key)

    if not client.api_key:
        print("[-] Error: No API key configured")
        print("[!] Set DEFECTDOJO_API_KEY environment variable or use --api-key")
        return 1

    print("\n" + "=" * 70)
    print("[*] DefectDojo API Client")
    print(f"[*] URL: {client.base_url}")
    print("=" * 70 + "\n")

    # Test connection
    if args.test_connection:
        if client.test_connection():
            print("[+] Connection successful")
            return 0
        print("[-] Connection failed")
        return 1

    # List products
    if args.list_products:
        products = client.list_products()

        if products:
            print(f"[+] Found {len(products)} products:")
            for product in products:
                print(f"    [{product['id']}] {product['name']}")
        else:
            print("[-] No products found")

        return 0

    # List engagements
    if args.list_engagements:
        engagements = client.list_engagements(product_id=args.product_id)

        if engagements:
            print(f"[+] Found {len(engagements)} engagements:")
            for engagement in engagements:
                print(f"    [{engagement['id']}] {engagement['name']} - {engagement['status']}")
        else:
            print("[-] No engagements found")

        return 0

    # Create engagement
    if args.create_engagement:
        if not args.product_id or not args.engagement_name:
            print("[-] Error: --product-id and --engagement-name required")
            return 1

        engagement = client.create_engagement(
            product_id=args.product_id,
            name=args.engagement_name,
            description=f"Created by Offensive Security Toolkit on {datetime.now().strftime('%Y-%m-%d')}",
        )

        if engagement:
            print(f"[+] Created engagement: {engagement['id']} - {engagement['name']}")
            args.engagement_id = engagement["id"]
        else:
            print("[-] Failed to create engagement")
            return 1

    # Upload scans
    if args.scan_file:
        if not args.engagement_id:
            print("[-] Error: --engagement-id required for uploads")
            return 1

        result = client.upload_scan(
            engagement_id=args.engagement_id, scan_file=args.scan_file, scan_type=args.scan_type
        )

        if result:
            print(f"[+] Uploaded {args.scan_file.name}")
            return 0
        print("[-] Upload failed")
        return 1

    if args.scan_dir:
        if not args.engagement_id:
            print("[-] Error: --engagement-id required for uploads")
            return 1

        stats = client.bulk_upload(engagement_id=args.engagement_id, scan_dir=args.scan_dir)

        print("\n[+] Upload Summary:")
        print(f"    Total: {stats['total']}")
        print(f"    Success: {stats['success']}")
        print(f"    Failed: {stats['failed']}")

        return 0 if stats["failed"] == 0 else 1

    # No action specified
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
