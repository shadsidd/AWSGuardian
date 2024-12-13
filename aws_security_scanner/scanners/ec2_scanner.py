# aws_security_scanner/scanners/ec2_scanner.py
from ..core.base_scanner import BaseScanner
from ..core.exceptions import ScannerError
from typing import Dict, List, Any

class EC2Scanner(BaseScanner):
    """Scanner for EC2 service"""

    async def scan(self) -> None:
        """Scan EC2 instances and related resources"""
        try:
            ec2 = self.session.client('ec2')

            # Scan instances
            instances = await self._get_all_instances(ec2)
            for instance in instances:
                await self._scan_instance_security(instance)

            # Scan security groups
            security_groups = await self._get_all_security_groups(ec2)
            for sg in security_groups:
                await self._scan_security_group(sg)

            # Scan network ACLs
            nacls = await self._get_all_network_acls(ec2)
            for nacl in nacls:
                await self._scan_network_acl(nacl)

            # Scan EBS volumes
            volumes = await self._get_all_volumes(ec2)
            for volume in volumes:
                await self._scan_volume_encryption(volume)

            # Scan VPC endpoints
            endpoints = await self._get_all_vpc_endpoints(ec2)
            for endpoint in endpoints:
                await self._scan_vpc_endpoint(endpoint)

        except Exception as e:
            raise ScannerError(f"EC2 scan failed: {str(e)}")

    async def _get_all_instances(self, ec2) -> List[Dict[str, Any]]:
        """Get all EC2 instances"""
        instances = []
        paginator = ec2.get_paginator('describe_instances')
        async for page in paginator.paginate():
            for reservation in page['Reservations']:
                instances.extend(reservation['Instances'])
        return instances

    async def _get_all_security_groups(self, ec2) -> List[Dict[str, Any]]:
        """Get all security groups"""
        groups = []
        paginator = ec2.get_paginator('describe_security_groups')
        async for page in paginator.paginate():
            groups.extend(page['SecurityGroups'])
        return groups

    async def _get_all_network_acls(self, ec2) -> List[Dict[str, Any]]:
        """Get all network ACLs"""
        nacls = []
        paginator = ec2.get_paginator('describe_network_acls')
        async for page in paginator.paginate():
            nacls.extend(page['NetworkAcls'])
        return nacls

    async def _get_all_volumes(self, ec2) -> List[Dict[str, Any]]:
        """Get all EBS volumes"""
        volumes = []
        paginator = ec2.get_paginator('describe_volumes')
        async for page in paginator.paginate():
            volumes.extend(page['Volumes'])
        return volumes

    async def _get_all_vpc_endpoints(self, ec2) -> List[Dict[str, Any]]:
        """Get all VPC endpoints"""
        endpoints = []
        paginator = ec2.get_paginator('describe_vpc_endpoints')
        async for page in paginator.paginate():
            endpoints.extend(page['VpcEndpoints'])
        return endpoints

    async def _scan_instance_security(self, instance: Dict[str, Any]) -> None:
        """Scan EC2 instance for security issues"""
        instance_id = instance['InstanceId']

        # Check for public IP
        if instance.get('PublicIpAddress'):
            risk_factors = {
                'network_exposure': 7,
                'public_access': 6
            }

            self.add_finding(
                service="EC2",
                resource=f"Instance/{instance_id}",
                risk_factors=risk_factors,
                description=f"Instance {instance_id} has a public IP address",
                recommendation="Review if public IP is necessary, consider using VPC endpoints",
                details={"public_ip": instance['PublicIpAddress']}
            )

        # Check for IMDSv2
        if not self._is_imdsv2_required(instance):
            risk_factors = {
                'metadata_security': 8,
                'vulnerability': 7
            }

            self.add_finding(
                service="EC2",
                resource=f"Instance/{instance_id}",
                risk_factors=risk_factors,
                description=f"Instance {instance_id} does not require IMDSv2",
                recommendation="Configure instance to require IMDSv2",
                details={"metadata_options": instance.get('MetadataOptions', {})}
            )

        # Check for unencrypted volumes
        for block_device in instance.get('BlockDeviceMappings', []):
            if 'Ebs' in block_device and not block_device['Ebs'].get('Encrypted'):
                risk_factors = {
                    'encryption': 6,
                    'data_protection': 5
                }

                self.add_finding(
                    service="EC2",
                    resource=f"Instance/{instance_id}",
                    risk_factors=risk_factors,
                    description=f"Instance {instance_id} has unencrypted EBS volumes",
                    recommendation="Enable EBS encryption for all volumes",
                    details={"volume_id": block_device['Ebs'].get('VolumeId')}
                )

    async def _scan_security_group(self, security_group: Dict[str, Any]) -> None:
        """Scan security group for risky configurations"""
        sg_id = security_group['GroupId']

        # Check inbound rules
        for rule in security_group.get('IpPermissions', []):
            if self._is_rule_risky(rule):
                risk_factors = {
                    'network_exposure': 9,
                    'security_group': 8
                }

                self.add_finding(
                    service="EC2",
                    resource=f"SecurityGroup/{sg_id}",
                    risk_factors=risk_factors,
                    description=f"Security group {sg_id} has overly permissive inbound rules",
                    recommendation="Restrict security group rules to specific IP ranges",
                    details={"rule": rule}
                )

    async def _scan_network_acl(self, nacl: Dict[str, Any]) -> None:
        """Scan network ACL for risky configurations"""
        nacl_id = nacl['NetworkAclId']

        for entry in nacl.get('Entries', []):
            if self._is_nacl_entry_risky(entry):
                risk_factors = {
                    'network_exposure': 7,
                    'access_control': 6
                }

                self.add_finding(
                    service="EC2",
                    resource=f"NetworkACL/{nacl_id}",
                    risk_factors=risk_factors,
                    description=f"Network ACL {nacl_id} has overly permissive rules",
                    recommendation="Review and restrict network ACL rules",
                    details={"entry": entry}
                )

    async def _scan_volume_encryption(self, volume: Dict[str, Any]) -> None:
        """Scan EBS volume encryption"""
        volume_id = volume['VolumeId']

        if not volume.get('Encrypted'):
            risk_factors = {
                'encryption': 7,
                'data_protection': 6
            }

            self.add_finding(
                service="EC2",
                resource=f"Volume/{volume_id}",
                risk_factors=risk_factors,
                description=f"EBS volume {volume_id} is not encrypted",
                recommendation="Enable encryption for all EBS volumes",
                details={"volume_type": volume.get('VolumeType')}
            )

    async def _scan_vpc_endpoint(self, endpoint: Dict[str, Any]) -> None:
        """Scan VPC endpoint configuration"""
        endpoint_id = endpoint['VpcEndpointId']

        if not endpoint.get('PolicyDocument'):
            risk_factors = {
                'access_control': 5,
                'policy': 4
            }

            self.add_finding(
                service="EC2",
                resource=f"VpcEndpoint/{endpoint_id}",
                risk_factors=risk_factors,
                description=f"VPC endpoint {endpoint_id} has no policy attached",
                recommendation="Configure VPC endpoint policy to restrict access",
                details={"service_name": endpoint.get('ServiceName')}
            )

    def _is_imdsv2_required(self, instance: Dict[str, Any]) -> bool:
        """Check if IMDSv2 is required"""
        metadata_options = instance.get('MetadataOptions', {})
        return metadata_options.get('HttpTokens') == 'required'

    def _is_rule_risky(self, rule: Dict[str, Any]) -> bool:
        """Check if security group rule is risky"""
        # Check for 0.0.0.0/0 in IPv4
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True

        # Check for ::/0 in IPv6
        for ip_range in rule.get('Ipv6Ranges', []):
            if ip_range.get('CidrIpv6') == '::/0':
                return True

        return False

    def _is_nacl_entry_risky(self, entry: Dict[str, Any]) -> bool:
        """Check if NACL entry is risky"""
        return (
            entry.get('CidrBlock') == '0.0.0.0/0' and
            entry.get('RuleAction') == 'allow' and
            entry.get('Protocol') == '-1'  # All traffic
        )
