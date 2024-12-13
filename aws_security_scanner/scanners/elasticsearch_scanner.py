# aws_security_scanner/scanners/elasticsearch_scanner.py
from ..core.base_scanner import BaseScanner
from ..core.exceptions import ScannerError
from typing import Dict, List, Any

class ElasticsearchScanner(BaseScanner):
    """Scanner for Elasticsearch service"""

    async def scan(self) -> None:
        """Scan Elasticsearch domains for security issues"""
        try:
            es = self.session.client('elasticsearch')
            domains = await self._get_all_domains(es)

            for domain_name in domains:
                domain_config = await self._get_domain_config(es, domain_name)
                await self._scan_encryption_config(domain_config)
                await self._scan_network_config(domain_config)
                await self._scan_access_policies(domain_config)
                await self._scan_logging_config(domain_config)
                await self._scan_version_compliance(domain_config)
                await self._scan_backup_config(domain_config)
        except Exception as e:
            raise ScannerError(f"Elasticsearch scan failed: {str(e)}")

    async def _get_all_domains(self, es) -> List[str]:
        """Get all Elasticsearch domains"""
        domains = []
        paginator = es.get_paginator('list_domain_names')
        async for page in paginator.paginate():
            domains.extend([domain['DomainName'] for domain in page['DomainNames']])
        return domains

    async def _get_domain_config(self, es, domain_name: str) -> Dict[str, Any]:
        """Get domain configuration"""
        return es.describe_elasticsearch_domain_config(DomainName=domain_name)['DomainConfig']

    async def _scan_encryption_config(self, domain_config: Dict[str, Any]) -> None:
        """Check domain encryption settings"""
        encryption = domain_config.get('EncryptionAtRestOptions', {}).get('Options', {})

        if not encryption.get('Enabled'):
            risk_factors = {
                'encryption': 8,
                'data_protection': 7
            }

            self.add_finding(
                service="Elasticsearch",
                resource=f"Domain/{domain_config['DomainName']}",
                risk_factors=risk_factors,
                description="Domain encryption at rest is not enabled",
                recommendation="Enable encryption at rest using KMS"
            )

        # Check node-to-node encryption
        node_encryption = domain_config.get('NodeToNodeEncryptionOptions', {}).get('Options', {})
        if not node_encryption.get('Enabled'):
            risk_factors = {
                'encryption': 7,
                'data_protection': 6
            }

            self.add_finding(
                service="Elasticsearch",
                resource=f"Domain/{domain_config['DomainName']}",
                risk_factors=risk_factors,
                description="Node-to-node encryption is not enabled",
                recommendation="Enable node-to-node encryption"
            )


    async def _scan_network_config(self, domain_config: Dict[str, Any]) -> None:
        """Check domain network configuration"""
        vpc_options = domain_config.get('VPCOptions', {}).get('Options', {})

        if not vpc_options:
            risk_factors = {
                'network_exposure': 8,
                'access_control': 7
            }

            self.add_finding(
                service="Elasticsearch",
                resource=f"Domain/{domain_config['DomainName']}",
                risk_factors=risk_factors,
                description="Domain is not configured in a VPC",
                recommendation="Configure domain to run within a VPC"
            )

        # Check for public access
        public_access = domain_config.get('PublicAccessOptions', {}).get('Options', {})
        if public_access.get('Enabled'):
            risk_factors = {
                'public_access': 9,
                'network_exposure': 8
            }

            self.add_finding(
                service="Elasticsearch",
                resource=f"Domain/{domain_config['DomainName']}",
                risk_factors=risk_factors,
                description="Domain allows public access",
                recommendation="Disable public access and use VPC endpoints"
            )

    async def _scan_access_policies(self, domain_config: Dict[str, Any]) -> None:
        """Check domain access policies"""
        access_policies = domain_config.get('AccessPolicies', {}).get('Options', {})

        if not access_policies:
            risk_factors = {
                'access_control': 7,
                'policy': 6
            }

            self.add_finding(
                service="Elasticsearch",
                resource=f"Domain/{domain_config['DomainName']}",
                risk_factors=risk_factors,
                description="Domain has no access policies configured",
                recommendation="Configure access policies to restrict domain access"
            )
        else:
            # Check for overly permissive policies
            if self._is_policy_overly_permissive(access_policies):
                risk_factors = {
                    'access_control': 8,
                    'policy': 7
                }

                self.add_finding(
                    service="Elasticsearch",
                    resource=f"Domain/{domain_config['DomainName']}",
                    risk_factors=risk_factors,
                    description="Domain has overly permissive access policies",
                    recommendation="Review and restrict access policies",
                    details={"policy": access_policies}
                )

    async def _scan_logging_config(self, domain_config: Dict[str, Any]) -> None:
        """Check domain logging configuration"""
        log_options = domain_config.get('LogPublishingOptions', {}).get('Options', {})

        required_logs = ['INDEX_SLOW_LOGS', 'SEARCH_SLOW_LOGS', 'ES_APPLICATION_LOGS']
        for log_type in required_logs:
            if not log_options.get(log_type, {}).get('Enabled'):
                risk_factors = {
                    'monitoring': 5,
                    'observability': 4
                }

                self.add_finding(
                    service="Elasticsearch",
                    resource=f"Domain/{domain_config['DomainName']}",
                    risk_factors=risk_factors,
                    description=f"Domain logging not enabled for {log_type}",
                    recommendation=f"Enable {log_type} logging"
                )

    async def _scan_version_compliance(self, domain_config: Dict[str, Any]) -> None:
        """Check Elasticsearch version compliance"""
        version = domain_config.get('ElasticsearchVersion', {}).get('Options')

        if self._is_version_outdated(version):
            risk_factors = {
                'version_compliance': 6,
                'security_updates': 5
            }

            self.add_finding(
                service="Elasticsearch",
                resource=f"Domain/{domain_config['DomainName']}",
                risk_factors=risk_factors,
                description=f"Domain running outdated Elasticsearch version {version}",
                recommendation="Upgrade to latest Elasticsearch version"
            )

    async def _scan_backup_config(self, domain_config: Dict[str, Any]) -> None:
        """Check domain backup configuration"""
        snapshot_options = domain_config.get('SnapshotOptions', {}).get('Options', {})

        if not snapshot_options.get('AutomatedSnapshotStartHour'):
            risk_factors = {
                'disaster_recovery': 6,
                'data_protection': 5
            }

            self.add_finding(
                service="Elasticsearch",
                resource=f"Domain/{domain_config['DomainName']}",
                risk_factors=risk_factors,
                description="Automated snapshots not configured",
                recommendation="Enable automated snapshots"
            )

    def _is_policy_overly_permissive(self, policy: Dict[str, Any]) -> bool:
        """Check if access policy is overly permissive"""
        if isinstance(policy, str):
            import json
            policy = json.loads(policy)

        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                if principal == '*' or principal.get('AWS') == '*':
                    return True

                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]

                if 'es:*' in actions:
                    return True

        return False

    def _is_version_outdated(self, version: str) -> bool:
        """Check if Elasticsearch version is outdated"""
        try:
            major_version = int(version.split('.')[0])
            return major_version < 7  # Consider versions below 7.x as outdated
        except (ValueError, AttributeError):
            return True
