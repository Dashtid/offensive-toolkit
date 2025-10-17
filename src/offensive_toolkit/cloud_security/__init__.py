"""
Cloud Security Testing Module

Comprehensive cloud security assessment tools for AWS, Azure, and GCP.
Aligned with MITRE ATT&CK for Cloud (IaaS).

MITRE ATT&CK Mapping:
- TA0042: Resource Development
- TA0007: Discovery
- TA0006: Credential Access

Modules:
- aws_scanner: AWS security misconfigurations and IAM analysis
- azure_scanner: Azure security misconfigurations and AD analysis
- gcp_scanner: GCP security misconfigurations and IAM analysis
- cloud_cli: Unified multi-cloud security scanning interface
"""

from .aws_scanner import AWSScanner
from .azure_scanner import AzureScanner
from .gcp_scanner import GCPScanner

__all__ = ["AWSScanner", "AzureScanner", "GCPScanner"]
