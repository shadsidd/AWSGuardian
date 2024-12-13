# aws_security_scanner/scanners/lambda_scanner.py
from ..core.base_scanner import BaseScanner
from ..core.exceptions import ScannerError
from typing import Dict, List, Any
import json

class LambdaScanner(BaseScanner):
    """Scanner for Lambda service"""

    async def scan(self) -> None:
        """Scan Lambda functions for security issues"""
        try:
            lambda_client = self.session.client('lambda')
            functions = await self._get_all_functions(lambda_client)

            for function in functions:
                await self._scan_function_configuration(function)
                await self._scan_function_policy(lambda_client, function)
                await self._scan_environment_variables(function)
                await self._scan_vpc_configuration(function)
                await self._scan_runtime(function)
                await self._scan_tracing_config(function)
        except Exception as e:
            raise ScannerError(f"Lambda scan failed: {str(e)}")

    async def _get_all_functions(self, lambda_client) -> List[Dict[str, Any]]:
        """Get all Lambda functions"""
        functions = []
        paginator = lambda_client.get_paginator('list_functions')
        async for page in paginator.paginate():
            functions.extend(page['Functions'])
        return functions

    async def _scan_function_configuration(self, function: Dict[str, Any]) -> None:
        """Scan Lambda function configuration"""
        function_name = function['FunctionName']

        # Check timeout configuration
        if function.get('Timeout', 0) > 900:  # 15 minutes
            risk_factors = {
                'resource_management': 4,
                'cost': 3
            }

            self.add_finding(
                service="Lambda",
                resource=f"Function/{function_name}",
                risk_factors=risk_factors,
                description=f"Function {function_name} has a high timeout value",
                recommendation="Review and adjust timeout settings",
                details={"timeout": function['Timeout']}
            )

        # Check memory configuration
        if function.get('MemorySize', 0) > 1024:  # 1GB
            risk_factors = {
                'resource_management': 4,
                'cost': 3
            }

            self.add_finding(
                service="Lambda",
                resource=f"Function/{function_name}",
                risk_factors=risk_factors,
                description=f"Function {function_name} has high memory allocation",
                recommendation="Review memory requirements",
                details={"memory_size": function['MemorySize']}
            )

    async def _scan_function_policy(self, lambda_client, function: Dict[str, Any]) -> None:
        """Scan Lambda function policy"""
        function_name = function['FunctionName']

        try:
            policy = lambda_client.get_policy(FunctionName=function_name)
            policy_json = json.loads(policy['Policy'])

            for statement in policy_json.get('Statement', []):
                if self._is_policy_overly_permissive(statement):
                    risk_factors = {
                        'access_control': 8,
                        'policy': 7
                    }

                    self.add_finding(
                        service="Lambda",
                        resource=f"Function/{function_name}",
                        risk_factors=risk_factors,
                        description=f"Function {function_name} has overly permissive resource policy",
                        recommendation="Restrict function policy permissions",
                        details={"statement": statement}
                    )
        except lambda_client.exceptions.ResourceNotFoundException:
            pass
        except Exception as e:
            self.logger.error(f"Failed to check policy for function {function_name}: {str(e)}")

    async def _scan_environment_variables(self, function: Dict[str, Any]) -> None:
        """Scan Lambda environment variables"""
        function_name = function['FunctionName']
        env_vars = function.get('Environment', {}).get('Variables', {})

        if not function.get('KMSKeyArn') and env_vars:
            risk_factors = {
                'encryption': 7,
                'secret_management': 6
            }

            self.add_finding(
                service="Lambda",
                resource=f"Function/{function_name}",
                risk_factors=risk_factors,
                description=f"Function {function_name} environment variables are not encrypted",
                recommendation="Enable KMS encryption for environment variables"
            )

        # Check for sensitive information in environment variables
        sensitive_patterns = ['key', 'secret', 'password', 'token', 'credential']
        for key in env_vars.keys():
            if any(pattern in key.lower() for pattern in sensitive_patterns):
                risk_factors = {
                    'secret_management': 8,
                    'best_practice': 6
                }

                self.add_finding(
                    service="Lambda",
                    resource=f"Function/{function_name}",
                    risk_factors=risk_factors,
                    description=f"Function {function_name} may have sensitive information in environment variables",
                    recommendation="Use AWS Secrets Manager for sensitive information",
                    details={"variable_name": key}
                )

    async def _scan_vpc_configuration(self, function: Dict[str, Any]) -> None:
        """Scan Lambda VPC configuration"""
        function_name = function['FunctionName']
        vpc_config = function.get('VpcConfig', {})

        if not vpc_config.get('VpcId'):
            risk_factors = {
                'network_isolation': 5,
                'best_practice': 4
            }

            self.add_finding(
                service="Lambda",
                resource=f"Function/{function_name}",
                risk_factors=risk_factors,
                description=f"Function {function_name} is not configured to run in a VPC",
                recommendation="Consider running function in a VPC for network isolation",
                details={"current_config": vpc_config}
            )

    async def _scan_runtime(self, function: Dict[str, Any]) -> None:
        """Scan Lambda runtime configuration"""
        function_name = function['FunctionName']
        runtime = function.get('Runtime', '')

        deprecated_runtimes = ['nodejs8.10', 'nodejs10.x', 'python2.7', 'python3.6']
        if runtime in deprecated_runtimes:
            risk_factors = {
                'vulnerability': 7,
                'maintenance': 6
            }

            self.add_finding(
                service="Lambda",
                resource=f"Function/{function_name}",
                risk_factors=risk_factors,
                description=f"Function {function_name} uses deprecated runtime {runtime}",
                recommendation="Upgrade to a supported runtime version"
            )

    async def _scan_tracing_config(self, function: Dict[str, Any]) -> None:
        """Scan Lambda tracing configuration"""
        function_name = function['FunctionName']
        tracing_config = function.get('TracingConfig', {})

        if tracing_config.get('Mode') != 'Active':
            risk_factors = {
                'observability': 4,
                'monitoring': 3
            }

            self.add_finding(
                service="Lambda",
                resource=f"Function/{function_name}",
                risk_factors=risk_factors,
                description=f"Function {function_name} does not have active tracing",
                recommendation="Enable X-Ray tracing for better observability"
            )

    def _is_policy_overly_permissive(self, statement: Dict[str, Any]) -> bool:
        """Check if policy statement is overly permissive"""
        principal = statement.get('Principal', {})
        condition = statement.get('Condition', {})

        # Check for public access
        if principal == '*' or principal.get('AWS') == '*':
            return True

        # Check if there are no conditions
        if not condition:
            return True

        return False
