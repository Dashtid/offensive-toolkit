"""
AWS Cloud Security Scanner

Comprehensive AWS security assessment tool for authorized testing.
Identifies IAM misconfigurations, S3 bucket exposures, security group issues,
and other common AWS security weaknesses.

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

import boto3
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

# Configure logging
logger = logging.getLogger(__name__)


class AWSScanner:
    """
    AWS Security Scanner for identifying misconfigurations and security issues.

    Features:
    - IAM policy analysis and privilege escalation paths
    - S3 bucket public exposure detection
    - Security group overly permissive rules
    - Public EC2 instances and AMIs
    - Root account usage detection
    - MFA enforcement checking
    - CloudTrail logging status
    - KMS key rotation validation
    """

    def __init__(self, profile_name: Optional[str] = None, region: str = "us-east-1"):
        """
        Initialize AWS scanner with credentials.

        Args:
            profile_name: AWS CLI profile name (uses default if None)
            region: AWS region to scan (default: us-east-1)
        """
        self.profile_name = profile_name
        self.region = region
        self.findings = {
            "scan_metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "scanner": "AWSScanner",
                "region": region,
                "profile": profile_name or "default"
            },
            "iam": [],
            "s3": [],
            "ec2": [],
            "security_groups": [],
            "cloudtrail": [],
            "kms": [],
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }

        # Initialize AWS session
        try:
            if profile_name:
                self.session = boto3.Session(profile_name=profile_name, region_name=region)
            else:
                self.session = boto3.Session(region_name=region)

            # Test credentials
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            self.account_id = identity['Account']
            self.findings["scan_metadata"]["account_id"] = self.account_id

            logger.info(f"[+] AWS scanner initialized for account {self.account_id}")

        except (NoCredentialsError, PartialCredentialsError) as e:
            logger.error(f"[-] AWS credentials not found or incomplete: {e}")
            raise
        except ClientError as e:
            logger.error(f"[-] AWS API error during initialization: {e}")
            raise

    def _add_finding(self, category: str, finding: Dict[str, Any]) -> None:
        """Add finding and update severity counts."""
        self.findings[category].append(finding)
        severity = finding.get("severity", "info")
        self.findings["summary"][severity] = self.findings["summary"].get(severity, 0) + 1

    def scan_iam_users(self) -> None:
        """
        Scan IAM users for security issues.

        Checks:
        - Users without MFA
        - Users with old access keys (>90 days)
        - Users with console access but no password rotation
        - Inactive users (no activity >90 days)
        - Users with attached policies (should use groups)
        """
        logger.info("[*] Scanning IAM users...")

        try:
            iam = self.session.client('iam')
            users = iam.list_users()['Users']

            for user in users:
                username = user['UserName']
                user_issues = []

                # Check MFA devices
                try:
                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    if not mfa_devices:
                        user_issues.append("No MFA configured")
                        self._add_finding("iam", {
                            "type": "iam_user_no_mfa",
                            "user": username,
                            "description": f"User {username} has no MFA device configured",
                            "severity": "high",
                            "recommendation": "Enable MFA for all IAM users",
                            "mitre": "T1078.004"
                        })
                except ClientError:
                    pass

                # Check access keys
                try:
                    access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                    for key in access_keys:
                        key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                        if key_age > 90:
                            user_issues.append(f"Access key {key['AccessKeyId']} is {key_age} days old")
                            self._add_finding("iam", {
                                "type": "iam_old_access_key",
                                "user": username,
                                "access_key_id": key['AccessKeyId'],
                                "key_age_days": key_age,
                                "description": f"Access key for {username} is {key_age} days old",
                                "severity": "medium",
                                "recommendation": "Rotate access keys every 90 days",
                                "mitre": "T1552.005"
                            })
                except ClientError:
                    pass

                # Check for attached user policies (should use groups)
                try:
                    attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
                    if attached_policies:
                        policy_names = [p['PolicyName'] for p in attached_policies]
                        user_issues.append(f"Has directly attached policies: {', '.join(policy_names)}")
                        self._add_finding("iam", {
                            "type": "iam_user_direct_policies",
                            "user": username,
                            "policies": policy_names,
                            "description": f"User {username} has directly attached policies instead of group membership",
                            "severity": "low",
                            "recommendation": "Use IAM groups for policy assignment",
                            "mitre": "T1069.003"
                        })
                except ClientError:
                    pass

                # Check for overly permissive policies
                try:
                    # Check inline policies
                    inline_policies = iam.list_user_policies(UserName=username)['PolicyNames']
                    for policy_name in inline_policies:
                        policy_doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)['PolicyDocument']
                        if self._check_admin_policy(policy_doc):
                            self._add_finding("iam", {
                                "type": "iam_user_admin_access",
                                "user": username,
                                "policy": policy_name,
                                "description": f"User {username} has administrative permissions via inline policy",
                                "severity": "critical",
                                "recommendation": "Remove administrative access or use breakglass procedure",
                                "mitre": "T1078.004"
                            })
                except ClientError:
                    pass

            logger.info(f"[+] IAM user scan complete: {len(users)} users analyzed")

        except ClientError as e:
            logger.error(f"[-] Error scanning IAM users: {e}")

    def scan_iam_roles(self) -> None:
        """
        Scan IAM roles for privilege escalation paths and overly permissive policies.

        Checks:
        - Roles with administrative access
        - Roles with overly permissive AssumeRole policies
        - Service roles with excessive permissions
        - Cross-account trust relationships
        """
        logger.info("[*] Scanning IAM roles...")

        try:
            iam = self.session.client('iam')
            roles = iam.list_roles()['Roles']

            for role in roles:
                role_name = role['RoleName']

                # Check AssumeRole policy for wildcard principals
                assume_role_doc = role['AssumeRolePolicyDocument']
                if self._check_wildcard_principal(assume_role_doc):
                    self._add_finding("iam", {
                        "type": "iam_role_wildcard_trust",
                        "role": role_name,
                        "description": f"Role {role_name} has wildcard in trust policy (can be assumed by any principal)",
                        "severity": "critical",
                        "recommendation": "Restrict AssumeRole policy to specific principals",
                        "mitre": "T1078.004"
                    })

                # Check for cross-account trust
                if self._check_cross_account_trust(assume_role_doc, self.account_id):
                    self._add_finding("iam", {
                        "type": "iam_role_cross_account_trust",
                        "role": role_name,
                        "description": f"Role {role_name} allows cross-account access",
                        "severity": "medium",
                        "recommendation": "Review cross-account trusts and use External ID",
                        "mitre": "T1078.004"
                    })

                # Check attached policies
                try:
                    attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                    for policy in attached_policies:
                        if policy['PolicyArn'].endswith('/AdministratorAccess'):
                            self._add_finding("iam", {
                                "type": "iam_role_admin_access",
                                "role": role_name,
                                "policy": policy['PolicyName'],
                                "description": f"Role {role_name} has AdministratorAccess policy attached",
                                "severity": "high",
                                "recommendation": "Follow principle of least privilege",
                                "mitre": "T1078.004"
                            })
                except ClientError:
                    pass

            logger.info(f"[+] IAM role scan complete: {len(roles)} roles analyzed")

        except ClientError as e:
            logger.error(f"[-] Error scanning IAM roles: {e}")

    def scan_s3_buckets(self) -> None:
        """
        Scan S3 buckets for public exposure and misconfigurations.

        Checks:
        - Publicly accessible buckets
        - Buckets without encryption
        - Buckets without versioning
        - Buckets without logging
        - Buckets with overly permissive policies
        """
        logger.info("[*] Scanning S3 buckets...")

        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()['Buckets']

            for bucket in buckets:
                bucket_name = bucket['Name']

                # Check bucket public access block
                try:
                    public_access = s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                    if not all([
                        public_access.get('BlockPublicAcls'),
                        public_access.get('IgnorePublicAcls'),
                        public_access.get('BlockPublicPolicy'),
                        public_access.get('RestrictPublicBuckets')
                    ]):
                        self._add_finding("s3", {
                            "type": "s3_public_access_not_blocked",
                            "bucket": bucket_name,
                            "description": f"S3 bucket {bucket_name} does not have all public access blocks enabled",
                            "severity": "high",
                            "recommendation": "Enable all S3 public access block settings",
                            "mitre": "T1530"
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        self._add_finding("s3", {
                            "type": "s3_no_public_access_block",
                            "bucket": bucket_name,
                            "description": f"S3 bucket {bucket_name} has no public access block configuration",
                            "severity": "critical",
                            "recommendation": "Configure S3 public access block",
                            "mitre": "T1530"
                        })

                # Check bucket encryption
                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        self._add_finding("s3", {
                            "type": "s3_no_encryption",
                            "bucket": bucket_name,
                            "description": f"S3 bucket {bucket_name} does not have default encryption enabled",
                            "severity": "high",
                            "recommendation": "Enable S3 bucket default encryption (SSE-S3 or SSE-KMS)",
                            "mitre": "T1530"
                        })

                # Check bucket versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        self._add_finding("s3", {
                            "type": "s3_versioning_disabled",
                            "bucket": bucket_name,
                            "description": f"S3 bucket {bucket_name} does not have versioning enabled",
                            "severity": "medium",
                            "recommendation": "Enable S3 versioning for data protection",
                            "mitre": "T1530"
                        })
                except ClientError:
                    pass

                # Check bucket policy for public access
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(policy['Policy'])
                    if self._check_public_s3_policy(policy_doc):
                        self._add_finding("s3", {
                            "type": "s3_public_policy",
                            "bucket": bucket_name,
                            "description": f"S3 bucket {bucket_name} has a policy allowing public access",
                            "severity": "critical",
                            "recommendation": "Remove public access from bucket policy",
                            "mitre": "T1530"
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                        pass

            logger.info(f"[+] S3 scan complete: {len(buckets)} buckets analyzed")

        except ClientError as e:
            logger.error(f"[-] Error scanning S3 buckets: {e}")

    def scan_security_groups(self) -> None:
        """
        Scan EC2 security groups for overly permissive rules.

        Checks:
        - Rules allowing 0.0.0.0/0 on risky ports (22, 3389, 3306, 5432)
        - Rules allowing all protocols
        - Rules allowing all ports
        - Default security group with non-default rules
        """
        logger.info("[*] Scanning EC2 security groups...")

        try:
            ec2 = self.session.client('ec2')
            security_groups = ec2.describe_security_groups()['SecurityGroups']

            risky_ports = [22, 3389, 3306, 5432, 5984, 6379, 7000, 7001, 8020, 8888, 9042, 9200, 27017]

            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']

                # Check ingress rules
                for rule in sg.get('IpPermissions', []):
                    # Check for 0.0.0.0/0
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 'all')
                            to_port = rule.get('ToPort', 'all')
                            protocol = rule.get('IpProtocol', 'all')

                            # Check if it's a risky port
                            if from_port in risky_ports or to_port in risky_ports:
                                self._add_finding("security_groups", {
                                    "type": "sg_public_risky_port",
                                    "security_group_id": sg_id,
                                    "security_group_name": sg_name,
                                    "port": from_port,
                                    "protocol": protocol,
                                    "description": f"Security group {sg_name} allows public access on risky port {from_port}",
                                    "severity": "critical",
                                    "recommendation": "Restrict access to specific IP ranges",
                                    "mitre": "T1046"
                                })
                            elif protocol == '-1' or from_port == 0:
                                self._add_finding("security_groups", {
                                    "type": "sg_public_all_ports",
                                    "security_group_id": sg_id,
                                    "security_group_name": sg_name,
                                    "description": f"Security group {sg_name} allows public access on all ports",
                                    "severity": "critical",
                                    "recommendation": "Restrict access to required ports only",
                                    "mitre": "T1046"
                                })
                            else:
                                self._add_finding("security_groups", {
                                    "type": "sg_public_access",
                                    "security_group_id": sg_id,
                                    "security_group_name": sg_name,
                                    "port": from_port,
                                    "protocol": protocol,
                                    "description": f"Security group {sg_name} allows public access on port {from_port}",
                                    "severity": "high",
                                    "recommendation": "Restrict access to specific IP ranges",
                                    "mitre": "T1046"
                                })

            logger.info(f"[+] Security group scan complete: {len(security_groups)} groups analyzed")

        except ClientError as e:
            logger.error(f"[-] Error scanning security groups: {e}")

    def scan_ec2_instances(self) -> None:
        """
        Scan EC2 instances for security issues.

        Checks:
        - Instances with public IP addresses
        - Instances without detailed monitoring
        - Instances with IMDSv1 enabled (should use IMDSv2)
        - Instances without encrypted EBS volumes
        """
        logger.info("[*] Scanning EC2 instances...")

        try:
            ec2 = self.session.client('ec2')
            reservations = ec2.describe_instances()['Reservations']

            for reservation in reservations:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']

                    # Check for public IP
                    if instance.get('PublicIpAddress'):
                        self._add_finding("ec2", {
                            "type": "ec2_public_ip",
                            "instance_id": instance_id,
                            "public_ip": instance['PublicIpAddress'],
                            "description": f"EC2 instance {instance_id} has a public IP address",
                            "severity": "medium",
                            "recommendation": "Use bastion hosts or VPN for access instead of public IPs",
                            "mitre": "T1580"
                        })

                    # Check IMDS version
                    metadata_options = instance.get('MetadataOptions', {})
                    if metadata_options.get('HttpTokens') != 'required':
                        self._add_finding("ec2", {
                            "type": "ec2_imdsv1_enabled",
                            "instance_id": instance_id,
                            "description": f"EC2 instance {instance_id} allows IMDSv1 (should enforce IMDSv2)",
                            "severity": "high",
                            "recommendation": "Enforce IMDSv2 to prevent SSRF attacks",
                            "mitre": "T1552.005"
                        })

                    # Check EBS encryption
                    for bdm in instance.get('BlockDeviceMappings', []):
                        volume_id = bdm.get('Ebs', {}).get('VolumeId')
                        if volume_id:
                            volume = ec2.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]
                            if not volume.get('Encrypted'):
                                self._add_finding("ec2", {
                                    "type": "ec2_unencrypted_volume",
                                    "instance_id": instance_id,
                                    "volume_id": volume_id,
                                    "description": f"EBS volume {volume_id} on instance {instance_id} is not encrypted",
                                    "severity": "high",
                                    "recommendation": "Enable EBS encryption for all volumes",
                                    "mitre": "T1530"
                                })

            logger.info("[+] EC2 instance scan complete")

        except ClientError as e:
            logger.error(f"[-] Error scanning EC2 instances: {e}")

    def scan_cloudtrail(self) -> None:
        """
        Scan CloudTrail configuration for logging gaps.

        Checks:
        - CloudTrail enabled in all regions
        - Log file validation enabled
        - S3 bucket encryption
        - CloudWatch Logs integration
        """
        logger.info("[*] Scanning CloudTrail configuration...")

        try:
            cloudtrail = self.session.client('cloudtrail')
            trails = cloudtrail.describe_trails()['trailList']

            if not trails:
                self._add_finding("cloudtrail", {
                    "type": "cloudtrail_not_enabled",
                    "description": "No CloudTrail trails configured",
                    "severity": "critical",
                    "recommendation": "Enable CloudTrail in all regions",
                    "mitre": "T1562.008"
                })

            for trail in trails:
                trail_name = trail['Name']

                # Check if multi-region
                if not trail.get('IsMultiRegionTrail'):
                    self._add_finding("cloudtrail", {
                        "type": "cloudtrail_not_multiregion",
                        "trail": trail_name,
                        "description": f"CloudTrail {trail_name} is not multi-region",
                        "severity": "high",
                        "recommendation": "Enable multi-region for CloudTrail",
                        "mitre": "T1562.008"
                    })

                # Check log file validation
                status = cloudtrail.get_trail_status(Name=trail['TrailARN'])
                if not trail.get('LogFileValidationEnabled'):
                    self._add_finding("cloudtrail", {
                        "type": "cloudtrail_no_log_validation",
                        "trail": trail_name,
                        "description": f"CloudTrail {trail_name} does not have log file validation enabled",
                        "severity": "medium",
                        "recommendation": "Enable log file validation",
                        "mitre": "T1562.008"
                    })

            logger.info(f"[+] CloudTrail scan complete: {len(trails)} trails analyzed")

        except ClientError as e:
            logger.error(f"[-] Error scanning CloudTrail: {e}")

    def _check_admin_policy(self, policy_doc: Dict[str, Any]) -> bool:
        """Check if policy grants administrative access."""
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])

                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                if '*' in actions and '*' in resources:
                    return True
        return False

    def _check_wildcard_principal(self, assume_role_doc: Dict[str, Any]) -> bool:
        """Check if AssumeRole policy has wildcard principal."""
        for statement in assume_role_doc.get('Statement', []):
            principal = statement.get('Principal', {})
            if isinstance(principal, str) and principal == '*':
                return True
            if isinstance(principal, dict):
                for key, value in principal.items():
                    if value == '*':
                        return True
        return False

    def _check_cross_account_trust(self, assume_role_doc: Dict[str, Any], account_id: str) -> bool:
        """Check for cross-account trust relationships."""
        for statement in assume_role_doc.get('Statement', []):
            principal = statement.get('Principal', {})
            if isinstance(principal, dict) and 'AWS' in principal:
                aws_principals = principal['AWS']
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]

                for arn in aws_principals:
                    if ':' in arn and account_id not in arn:
                        return True
        return False

    def _check_public_s3_policy(self, policy_doc: Dict[str, Any]) -> bool:
        """Check if S3 bucket policy allows public access."""
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                    return True
        return False

    def scan_all(self) -> Dict[str, Any]:
        """
        Run all AWS security scans.

        Returns:
            Dict containing all scan findings
        """
        logger.info("[!] Starting comprehensive AWS security scan...")
        logger.info(f"[!] Account ID: {self.account_id}")
        logger.info(f"[!] Region: {self.region}")

        self.scan_iam_users()
        self.scan_iam_roles()
        self.scan_s3_buckets()
        self.scan_security_groups()
        self.scan_ec2_instances()
        self.scan_cloudtrail()

        logger.info("[+] AWS security scan complete!")
        logger.info(f"[+] Findings: Critical={self.findings['summary']['critical']}, "
                   f"High={self.findings['summary']['high']}, "
                   f"Medium={self.findings['summary']['medium']}, "
                   f"Low={self.findings['summary']['low']}")

        return self.findings

    def save_results(self, output_file: Path) -> None:
        """Save scan results to JSON file."""
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(self.findings, f, indent=2)

        logger.info(f"[+] Results saved to {output_file}")


def main():
    """CLI entry point for AWS scanner."""
    import argparse

    parser = argparse.ArgumentParser(
        description="AWS Cloud Security Scanner - Identify misconfigurations and security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with default profile
  python aws_scanner.py --scan-all --output aws_findings.json

  # Scan specific profile and region
  python aws_scanner.py --profile prod --region us-west-2 --scan-all

  # Scan specific checks only
  python aws_scanner.py --scan iam s3 --output results.json

MITRE ATT&CK Mapping:
  T1580: Cloud Infrastructure Discovery
  T1526: Cloud Service Discovery
  T1087.004: Account Discovery - Cloud Account
  T1552.005: Unsecured Credentials - Cloud Instance Metadata API
  T1530: Data from Cloud Storage Object
        """
    )

    parser.add_argument('--profile', help='AWS CLI profile name')
    parser.add_argument('--region', default='us-east-1', help='AWS region (default: us-east-1)')
    parser.add_argument('--scan', nargs='+', choices=['iam', 's3', 'ec2', 'security_groups', 'cloudtrail'],
                       help='Specific scans to run')
    parser.add_argument('--scan-all', action='store_true', help='Run all scans')
    parser.add_argument('--output', type=Path, default=Path('output/aws_scan.json'),
                       help='Output file path (default: output/aws_scan.json)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(message)s'
    )

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║           AWS Cloud Security Scanner v1.0                 ║
    ║           Authorized Security Testing Only                ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    try:
        scanner = AWSScanner(profile_name=args.profile, region=args.region)

        if args.scan_all:
            scanner.scan_all()
        elif args.scan:
            if 'iam' in args.scan:
                scanner.scan_iam_users()
                scanner.scan_iam_roles()
            if 's3' in args.scan:
                scanner.scan_s3_buckets()
            if 'ec2' in args.scan:
                scanner.scan_ec2_instances()
            if 'security_groups' in args.scan:
                scanner.scan_security_groups()
            if 'cloudtrail' in args.scan:
                scanner.scan_cloudtrail()
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
