# aws_security_scanner/scanners/rds_scanner.py
from ..core.base_scanner import BaseScanner
from ..core.exceptions import ScannerError
from typing import Dict, List, Any

class RDSScanner(BaseScanner):
    """Scanner for RDS service"""

    async def scan(self) -> None:
        """Scan RDS instances for security issues"""
        try:
            rds = self.session.client('rds')
            instances = await self._get_all_instances(rds)

            for instance in instances:
                await self._scan_public_access(instance)
                await self._scan_encryption(instance)
                await self._scan_backup_retention(instance)
                await self._scan_security_groups(instance)
                await self._scan_multi_az(instance)
                await self._scan_minor_version_upgrade(instance)
        except Exception as e:
            raise ScannerError(f"RDS scan failed: {str(e)}")

    async def _get_all_instances(self, rds) -> List[Dict[str, Any]]:
        """Get all RDS instances"""
        instances = []
        paginator = rds.get_paginator('describe_db_instances')
        async for page in paginator.paginate():
            instances.extend(page['DBInstances'])
        return instances

    async def _scan_public_access(self, instance: Dict[str, Any]) -> None:
        """Check for public accessibility"""
        if instance.get('PubliclyAccessible'):
            risk_factors = {
                'public_access': 9,
                'network_exposure': 8
            }

            self.add_finding(
                service="RDS",
                resource=f"Instance/{instance['DBInstanceIdentifier']}",
                risk_factors=risk_factors,
                description=f"RDS instance {instance['DBInstanceIdentifier']} is publicly accessible",
                recommendation="Disable public accessibility for database instances",
                details={"endpoint": instance.get('Endpoint', {})}
            )

    async def _scan_encryption(self, instance: Dict[str, Any]) -> None:
        """Check encryption settings"""
        if not instance.get('StorageEncrypted'):
            risk_factors = {
                'encryption': 8,
                'data_protection': 7
            }

            self.add_finding(
                service="RDS",
                resource=f"Instance/{instance['DBInstanceIdentifier']}",
                risk_factors=risk_factors,
                description=f"RDS instance {instance['DBInstanceIdentifier']} is not encrypted",
                recommendation="Enable storage encryption for database instances"
            )

    async def _scan_backup_retention(self, instance: Dict[str, Any]) -> None:
        """Check backup retention period"""
        retention_period = instance.get('BackupRetentionPeriod', 0)
        if retention_period < 7:
            risk_factors = {
                'disaster_recovery': 6,
                'data_protection': 5
            }

            self.add_finding(
                service="RDS",
                resource=f"Instance/{instance['DBInstanceIdentifier']}",
                risk_factors=risk_factors,
                description=f"RDS instance {instance['DBInstanceIdentifier']} has insufficient backup retention period ({retention_period} days)",
                recommendation="Increase backup retention period to at least 7 days",
                details={"current_retention": retention_period}
            )

    async def _scan_security_groups(self, instance: Dict[str, Any]) -> None:
        """Check security group configurations"""
        ec2 = self.session.client('ec2')

        for sg in instance.get('VpcSecurityGroups', []):
            try:
                sg_info = ec2.describe_security_groups(GroupIds=[sg['VpcSecurityGroupId']])['SecurityGroups'][0]

                for rule in sg_info['IpPermissions']:
                    if self._has_wide_open_access(rule):
                        risk_factors = {
                            'network_exposure': 8,
                            'security_group': 7
                        }

                        self.add_finding(
                            service="RDS",
                            resource=f"Instance/{instance['DBInstanceIdentifier']}/SecurityGroup/{sg['VpcSecurityGroupId']}",
                            risk_factors=risk_factors,
                            description=f"RDS instance {instance['DBInstanceIdentifier']} has overly permissive security group rules",
                            recommendation="Restrict security group rules to specific IP ranges",
                            details={"security_group": sg_info}
                        )
            except Exception as e:
                self.logger.error(f"Failed to check security group {sg['VpcSecurityGroupId']}: {str(e)}")

    async def _scan_multi_az(self, instance: Dict[str, Any]) -> None:
        """Check Multi-AZ configuration"""
        if not instance.get('MultiAZ'):
            risk_factors = {
                'high_availability': 5,
                'disaster_recovery': 4
            }

            self.add_finding(
                service="RDS",
                resource=f"Instance/{instance['DBInstanceIdentifier']}",
                risk_factors=risk_factors,
                description=f"RDS instance {instance['DBInstanceIdentifier']} is not configured for Multi-AZ",
                recommendation="Enable Multi-AZ for high availability"
            )

    async def _scan_minor_version_upgrade(self, instance: Dict[str, Any]) -> None:
        """Check auto minor version upgrade setting"""
        if not instance.get('AutoMinorVersionUpgrade'):
            risk_factors = {
                'patch_management': 4,
                'vulnerability': 3
            }

            self.add_finding(
                service="RDS",
                resource=f"Instance/{instance['DBInstanceIdentifier']}",
                risk_factors=risk_factors,
                description=f"RDS instance {instance['DBInstanceIdentifier']} has automatic minor version upgrades disabled",
                recommendation="Enable automatic minor version upgrades"
            )

    def _has_wide_open_access(self, rule: Dict[str, Any]) -> bool:
        """Check if security group rule allows wide open access"""
        ip_ranges = rule.get('IpRanges', [])
        ipv6_ranges = rule.get('Ipv6Ranges', [])

        for ip_range in ip_ranges:
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True

        for ipv6_range in ipv6_ranges:
            if ipv6_range.get('CidrIpv6') == '::/0':
                return True

        return False
