# aws_security_scanner/scanners/s3_scanner.py
from ..core.base_scanner import BaseScanner
from ..core.exceptions import ScannerError
from typing import Dict, List, Any
import json

class S3Scanner(BaseScanner):
    """Scanner for S3 service"""

    async def scan(self) -> None:
        """Scan S3 buckets for security issues"""
        try:
            s3 = self.session.client('s3')
            buckets = await self._get_all_buckets(s3)

            for bucket in buckets:
                await self._scan_bucket_acl(s3, bucket['Name'])
                await self._scan_bucket_policy(s3, bucket['Name'])
                await self._scan_encryption(s3, bucket['Name'])
                await self._scan_versioning(s3, bucket['Name'])
                await self._scan_public_access(s3, bucket['Name'])
                await self._scan_logging(s3, bucket['Name'])
        except Exception as e:
            raise ScannerError(f"S3 scan failed: {str(e)}")

    async def _get_all_buckets(self, s3) -> List[Dict[str, Any]]:
        """Get all S3 buckets"""
        return s3.list_buckets()['Buckets']

    async def _scan_bucket_acl(self, s3, bucket_name: str) -> None:
        """Check bucket ACL for public access"""
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)

            for grant in acl['Grants']:
                grantee = grant['Grantee']
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    risk_factors = {
                        'public_access': 9,
                        'data_exposure': 8
                    }

                    self.add_finding(
                        service="S3",
                        resource=f"Bucket/{bucket_name}",
                        risk_factors=risk_factors,
                        description=f"Bucket {bucket_name} has public access through ACL",
                        recommendation="Remove public access from bucket ACL",
                        details={"acl": acl}
                    )
        except Exception as e:
            self.logger.error(f"Failed to check ACL for bucket {bucket_name}: {str(e)}")

    async def _scan_bucket_policy(self, s3, bucket_name: str) -> None:
        """Check bucket policy for security issues"""
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy['Policy'])

            if self._has_public_access_policy(policy_json):
                risk_factors = {
                    'public_access': 8,
                    'policy_misconfiguration': 7
                }

                self.add_finding(
                    service="S3",
                    resource=f"Bucket/{bucket_name}",
                    risk_factors=risk_factors,
                    description=f"Bucket {bucket_name} has public access through bucket policy",
                    recommendation="Review and restrict bucket policy",
                    details={"policy": policy_json}
                )
        except s3.exceptions.NoSuchBucketPolicy:
            pass
        except Exception as e:
            self.logger.error(f"Failed to check policy for bucket {bucket_name}: {str(e)}")

    async def _scan_encryption(self, s3, bucket_name: str) -> None:
        """Check bucket encryption settings"""
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
        except s3.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                risk_factors = {
                    'encryption': 7,
                    'data_protection': 6
                }

                self.add_finding(
                    service="S3",
                    resource=f"Bucket/{bucket_name}",
                    risk_factors=risk_factors,
                    description=f"Bucket {bucket_name} does not have default encryption enabled",
                    recommendation="Enable default encryption for the bucket"
                )

    async def _scan_versioning(self, s3, bucket_name: str) -> None:
        """Check bucket versioning status"""
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                risk_factors = {
                    'data_protection': 5,
                    'disaster_recovery': 4
                }

                self.add_finding(
                    service="S3",
                    resource=f"Bucket/{bucket_name}",
                    risk_factors=risk_factors,
                    description=f"Bucket {bucket_name} does not have versioning enabled",
                    recommendation="Enable versioning for data protection"
                )
        except Exception as e:
            self.logger.error(f"Failed to check versioning for bucket {bucket_name}: {str(e)}")

    async def _scan_public_access(self, s3, bucket_name: str) -> None:
        """Check bucket public access block settings"""
        try:
            public_access = s3.get_public_access_block(Bucket=bucket_name)
            block_config = public_access['PublicAccessBlockConfiguration']

            if not all([
                block_config.get('BlockPublicAcls', False),
                block_config.get('IgnorePublicAcls', False),
                block_config.get('BlockPublicPolicy', False),
                block_config.get('RestrictPublicBuckets', False)
            ]):
                risk_factors = {
                    'public_access': 7,
                    'security_control': 6
                }

                self.add_finding(
                    service="S3",
                    resource=f"Bucket/{bucket_name}",
                    risk_factors=risk_factors,
                    description=f"Bucket {bucket_name} does not have all public access blocks enabled",
                    recommendation="Enable all public access block settings",
                    details={"public_access_config": block_config}
                )
        except Exception as e:
            self.logger.error(f"Failed to check public access block for bucket {bucket_name}: {str(e)}")

    async def _scan_logging(self, s3, bucket_name: str) -> None:
        """Check bucket logging configuration"""
        try:
            logging_config = s3.get_bucket_logging(Bucket=bucket_name)
            if 'LoggingEnabled' not in logging_config:
                risk_factors = {
                    'monitoring': 4,
                    'audit': 3
                }

                self.add_finding(
                    service="S3",
                    resource=f"Bucket/{bucket_name}",
                    risk_factors=risk_factors,
                    description=f"Bucket {bucket_name} does not have logging enabled",
                    recommendation="Enable logging for audit purposes"
                )
        except Exception as e:
            self.logger.error(f"Failed to check logging for bucket {bucket_name}: {str(e)}")

    def _has_public_access_policy(self, policy: Dict) -> bool:
        """Check if bucket policy allows public access"""
        for statement in policy.get('Statement', []):
            principal = statement.get('Principal', {})
            effect = statement.get('Effect', '')

            if effect == 'Allow' and (
                principal == '*' or
                principal.get('AWS') == '*' or
                principal.get('CanonicalUser') == '*'
            ):
                return True

        return False
