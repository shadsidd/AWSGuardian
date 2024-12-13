# aws_security_scanner/scanners/dynamodb_scanner.py
from ..core.base_scanner import BaseScanner
from ..core.exceptions import ScannerError
from typing import Dict, List, Any

class DynamoDBScanner(BaseScanner):
    """Scanner for DynamoDB service"""

    async def scan(self) -> None:
        """Scan DynamoDB tables for security issues"""
        try:
            dynamodb = self.session.client('dynamodb')
            tables = await self._get_all_tables(dynamodb)

            for table_name in tables:
                table = await self._get_table_details(dynamodb, table_name)
                await self._scan_table_encryption(table)
                await self._scan_backup_config(table)
                await self._scan_point_in_time_recovery(dynamodb, table_name)
                await self._scan_iam_policies(table_name)
                await self._scan_table_streams(table)
                await self._scan_auto_scaling(table)
        except Exception as e:
            raise ScannerError(f"DynamoDB scan failed: {str(e)}")

    async def _get_all_tables(self, dynamodb) -> List[str]:
        """Get all DynamoDB tables"""
        tables = []
        paginator = dynamodb.get_paginator('list_tables')
        async for page in paginator.paginate():
            tables.extend(page['TableNames'])
        return tables

    async def _get_table_details(self, dynamodb, table_name: str) -> Dict[str, Any]:
        """Get detailed information about a table"""
        return dynamodb.describe_table(TableName=table_name)['Table']

    async def _scan_table_encryption(self, table: Dict[str, Any]) -> None:
        """Check table encryption settings"""
        table_name = table['TableName']
        encryption = table.get('SSEDescription', {})

        if not encryption or encryption.get('Status') != 'ENABLED':
            risk_factors = {
                'encryption': 8,
                'data_protection': 7
            }

            self.add_finding(
                service="DynamoDB",
                resource=f"Table/{table_name}",
                risk_factors=risk_factors,
                description=f"Table {table_name} is not encrypted with AWS KMS",
                recommendation="Enable KMS encryption for the table",
                details={"current_encryption": encryption}
            )

    async def _scan_backup_config(self, table: Dict[str, Any]) -> None:
        """Check backup configuration"""
        table_name = table['TableName']
        backup_description = table.get('BackupDescription', {})

        if not backup_description:
            risk_factors = {
                'disaster_recovery': 6,
                'data_protection': 5
            }

            self.add_finding(
                service="DynamoDB",
                resource=f"Table/{table_name}",
                risk_factors=risk_factors,
                description=f"Table {table_name} has no backup configuration",
                recommendation="Enable continuous backups and point-in-time recovery"
            )

    async def _scan_point_in_time_recovery(self, dynamodb, table_name: str) -> None:
        """Check point-in-time recovery settings"""
        try:
            pitr = dynamodb.describe_continuous_backups(TableName=table_name)
            if not pitr.get('ContinuousBackupsDescription', {}).get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus') == 'ENABLED':
                risk_factors = {
                    'disaster_recovery': 7,
                    'data_protection': 6
                }

                self.add_finding(
                    service="DynamoDB",
                    resource=f"Table/{table_name}",
                    risk_factors=risk_factors,
                    description=f"Table {table_name} does not have point-in-time recovery enabled",
                    recommendation="Enable point-in-time recovery for data protection"
                )
        except Exception as e:
            self.logger.error(f"Failed to check PITR for table {table_name}: {str(e)}")

    async def _scan_iam_policies(self, table_name: str) -> None:
        """Check IAM policies associated with the table"""
        iam = self.session.client('iam')
        try:
            # Check for overly permissive policies
            policies = await self._get_table_policies(iam, table_name)

            for policy in policies:
                if self._is_policy_overly_permissive(policy):
                    risk_factors = {
                        'access_control': 8,
                        'policy': 7
                    }

                    self.add_finding(
                        service="DynamoDB",
                        resource=f"Table/{table_name}",
                        risk_factors=risk_factors,
                        description=f"Table {table_name} has overly permissive IAM policies",
                        recommendation="Review and restrict IAM policies",
                        details={"policy": policy}
                    )
        except Exception as e:
            self.logger.error(f"Failed to check IAM policies for table {table_name}: {str(e)}")

    async def _scan_table_streams(self, table: Dict[str, Any]) -> None:
        """Check DynamoDB Streams configuration"""
        table_name = table['TableName']
        stream_specification = table.get('StreamSpecification', {})

        if not stream_specification.get('StreamEnabled'):
            risk_factors = {
                'monitoring': 4,
                'data_tracking': 3
            }

            self.add_finding(
                service="DynamoDB",
                resource=f"Table/{table_name}",
                risk_factors=risk_factors,
                description=f"Table {table_name} does not have DynamoDB Streams enabled",
                recommendation="Consider enabling Streams for change data capture and auditing"
            )

    async def _scan_auto_scaling(self, table: Dict[str, Any]) -> None:
        """Check Auto Scaling configuration"""
        table_name = table['TableName']

        if not self._has_auto_scaling(table):
            risk_factors = {
                'performance': 5,
                'cost_optimization': 4
            }

            self.add_finding(
                service="DynamoDB",
                resource=f"Table/{table_name}",
                risk_factors=risk_factors,
                description=f"Table {table_name} does not have Auto Scaling configured",
                recommendation="Enable Auto Scaling for better performance and cost management"
            )

    async def _get_table_policies(self, iam, table_name: str) -> List[Dict[str, Any]]:
        """Get IAM policies related to the table"""
        policies = []
        paginator = iam.get_paginator('list_policies')

        async for page in paginator.paginate(Scope='Local'):
            for policy in page['Policies']:
                policy_version = iam.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=policy['DefaultVersionId']
                )['PolicyVersion']

                if self._policy_affects_table(policy_version['Document'], table_name):
                    policies.append(policy_version['Document'])

        return policies

    def _is_policy_overly_permissive(self, policy: Dict[str, Any]) -> bool:
        """Check if policy is overly permissive"""
        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]

                if 'dynamodb:*' in actions:
                    return True

                resource = statement.get('Resource', '')
                if resource == '*':
                    return True

        return False

    def _policy_affects_table(self, policy: Dict[str, Any], table_name: str) -> bool:
        """Check if policy affects specific table"""
        for statement in policy.get('Statement', []):
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]

            for resource in resources:
                if table_name in resource:
                    return True

        return False

    def _has_auto_scaling(self, table: Dict[str, Any]) -> bool:
        """Check if table has Auto Scaling enabled"""
        provisioned = table.get('ProvisionedThroughput', {})
        if not provisioned:
            return False

        application_auto_scaling = self.session.client('application-autoscaling')
        try:
            scalable_targets = application_auto_scaling.describe_scalable_targets(
                ServiceNamespace='dynamodb',
                ResourceIds=[f"table/{table['TableName']}"]
            )
            return len(scalable_targets['ScalableTargets']) > 0
        except Exception:
            return False
