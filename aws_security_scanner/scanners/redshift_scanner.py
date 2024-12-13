# aws_security_scanner/scanners/redshift_scanner.py
from ..core.base_scanner import BaseScanner
from ..core.exceptions import ScannerError
from typing import Dict, List, Any

class RedshiftScanner(BaseScanner):
    """Scanner for Redshift service"""

    async def scan(self) -> None:
        """Scan Redshift clusters for security issues"""
        try:
            redshift = self.session.client('redshift')
            clusters = await self._get_all_clusters(redshift)

            for cluster in clusters:
                await self._scan_encryption_config(cluster)
                await self._scan_network_config(cluster)
                await self._scan_parameter_groups(redshift, cluster)
                await self._scan_logging_config(cluster)
                await self._scan_snapshot_config(cluster)
                await self._scan_maintenance_config(cluster)
                await self._scan_audit_logging(cluster)
                await self._scan_vpc_routing(cluster)
        except Exception as e:
            raise ScannerError(f"Redshift scan failed: {str(e)}")

    async def _get_all_clusters(self, redshift) -> List[Dict[str, Any]]:
        """Get all Redshift clusters"""
        clusters = []
        paginator = redshift.get_paginator('describe_clusters')
        async for page in paginator.paginate():
            clusters.extend(page['Clusters'])
        return clusters

    async def _scan_encryption_config(self, cluster: Dict[str, Any]) -> None:
        """Check cluster encryption settings"""
        if not cluster.get('Encrypted'):
            risk_factors = {
                'encryption': 9,
                'data_protection': 8
            }

            self.add_finding(
                service="Redshift",
                resource=f"Cluster/{cluster['ClusterIdentifier']}",
                risk_factors=risk_factors,
                description="Cluster is not encrypted",
                recommendation="Enable encryption using KMS",
                details={"cluster_status": cluster.get('ClusterStatus')}
            )

    async def _scan_network_config(self, cluster: Dict[str, Any]) -> None:
        """Check network configuration"""
        # Check public accessibility
        if cluster.get('PubliclyAccessible'):
            risk_factors = {
                'network_exposure': 9,
                'access_control': 8
            }

            self.add_finding(
                service="Redshift",
                resource=f"Cluster/{cluster['ClusterIdentifier']}",
                risk_factors=risk_factors,
                description="Cluster is publicly accessible",
                recommendation="Disable public accessibility and use VPC endpoints"
            )

        # Check VPC security groups
        security_groups = cluster.get('VpcSecurityGroups', [])
        await self._check_security_groups(cluster['ClusterIdentifier'], security_groups)

    async def _scan_parameter_groups(self, redshift, cluster: Dict[str, Any]) -> None:
        """Check parameter group configurations"""
        parameter_group = cluster.get('ClusterParameterGroups', [])[0]
        if parameter_group:
            parameters = redshift.describe_cluster_parameters(
                ParameterGroupName=parameter_group['ParameterGroupName']
            )['Parameters']

            # Check SSL requirement
            ssl_param = next((p for p in parameters if p['ParameterName'] == 'require_ssl'), None)
            if not ssl_param or ssl_param.get('ParameterValue') != 'true':
                risk_factors = {
                    'encryption': 7,
                    'protocol_security': 6
                }

                self.add_finding(
                    service="Redshift",
                    resource=f"Cluster/{cluster['ClusterIdentifier']}",
                    risk_factors=risk_factors,
                    description="SSL is not required for connections",
                    recommendation="Enable SSL requirement in parameter group"
                )

    async def _scan_logging_config(self, cluster: Dict[str, Any]) -> None:
        """Check logging configuration"""
        logging_status = cluster.get('LoggingStatus', {})

        if not logging_status.get('LoggingEnabled'):
            risk_factors = {
                'monitoring': 6,
                'audit': 5
            }

            self.add_finding(
                service="Redshift",
                resource=f"Cluster/{cluster['ClusterIdentifier']}",
                risk_factors=risk_factors,
                description="Cluster logging is not enabled",
                recommendation="Enable cluster logging for audit purposes"
            )

    async def _scan_snapshot_config(self, cluster: Dict[str, Any]) -> None:
        """Check snapshot configuration"""
        retention_period = cluster.get('AutomatedSnapshotRetentionPeriod', 0)

        if retention_period < 7:
            risk_factors = {
                'backup': 7,
                'disaster_recovery': 6
            }

            self.add_finding(
                service="Redshift",
                resource=f"Cluster/{cluster['ClusterIdentifier']}",
                risk_factors=risk_factors,
                description=f"Short snapshot retention period ({retention_period} days)",
                recommendation="Increase snapshot retention period to at least 7 days"
            )

    async def _scan_maintenance_config(self, cluster: Dict[str, Any]) -> None:
        """Check maintenance configuration"""
        if not cluster.get('AllowVersionUpgrade'):
            risk_factors = {
                'patch_management': 6,
                'version_compliance': 5
            }

            self.add_finding(
                service="Redshift",
                resource=f"Cluster/{cluster['ClusterIdentifier']}",
                risk_factors=risk_factors,
                description="Automatic version upgrades are disabled",
                recommendation="Enable automatic version upgrades"
            )

    async def _scan_audit_logging(self, cluster: Dict[str, Any]) -> None:
        """Check audit logging configuration"""
        # Implementation depends on specific audit requirements
        pass

    async def _scan_vpc_routing(self, cluster: Dict[str, Any]) -> None:
        """Check VPC routing configuration"""
        if not cluster.get('EnhancedVpcRouting'):
            risk_factors = {
                'network_security': 5,
                'data_transfer': 4
            }

            self.add_finding(
                service="Redshift",
                resource=f"Cluster/{cluster['ClusterIdentifier']}",
                risk_factors=risk_factors,
                description="Enhanced VPC routing is not enabled",
                recommendation="Enable enhanced VPC routing for improved network security"
            )

    async def _check_security_groups(self, cluster_id: str, security_groups: List[Dict[str, Any]]) -> None:
        """Check security group configurations"""
        ec2 = self.session.client('ec2')

        for sg in security_groups:
            try:
                sg_info = ec2.describe_security_groups(
                    GroupIds=[sg['VpcSecurityGroupId']]
                )['SecurityGroups'][0]

                # Check for overly permissive rules
                for rule in sg_info['IpPermissions']:
                    if self._is_rule_overly_permissive(rule):
                        risk_factors = {
                            'network_security': 8,
                            'access_control': 7
                        }

                        self.add_finding(
                            service="Redshift",
                            resource=f"Cluster/{cluster_id}/SecurityGroup/{sg['VpcSecurityGroupId']}",
                            risk_factors=risk_factors,
                            description="Security group has overly permissive rules",
                            recommendation="Restrict security group rules",
                            details={"rule": rule}
                        )
            except Exception as e:
                self.logger.error(f"Failed to check security group {sg['VpcSecurityGroupId']}: {str(e)}")

    def _is_rule_overly_permissive(self, rule: Dict[str, Any]) -> bool:
        """Check if security group rule is overly permissive"""
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True

        for ip_range in rule.get('Ipv6Ranges', []):
            if ip_range.get('CidrIpv6') == '::/0':
                return True

        return False
