# aws_security_scanner/scanners/iam_scanner.py
from ..core.base_scanner import BaseScanner
from ..core.exceptions import ScannerError
import json
from typing import Dict, List, Any

class IAMScanner(BaseScanner):
    """Scanner for IAM service"""

    async def scan(self) -> None:
        """Scan IAM configurations"""
        try:
            await self._scan_password_policy()
            await self._scan_access_keys()
            await self._scan_roles()
            await self._scan_users()
            await self._scan_policies()
        except Exception as e:
            raise ScannerError(f"IAM scan failed: {str(e)}")

    async def _scan_password_policy(self) -> None:
        """Check password policy settings"""
        try:
            iam = self.session.client('iam')
            policy = iam.get_account_password_policy()['PasswordPolicy']

            if not policy.get('RequireUppercaseCharacters') or \
               not policy.get('RequireLowercaseCharacters') or \
               not policy.get('RequireSymbols') or \
               not policy.get('RequireNumbers') or \
               policy.get('MinimumPasswordLength', 0) < 14:

                risk_factors = {
                    'weak_authentication': 8,
                    'policy_violation': 6
                }

                self.add_finding(
                    service="IAM",
                    resource="PasswordPolicy",
                    risk_factors=risk_factors,
                    description="Weak password policy configuration",
                    recommendation="Enforce stronger password requirements"
                )
        except iam.exceptions.NoSuchEntityException:
            self.add_finding(
                service="IAM",
                resource="PasswordPolicy",
                risk_factors={'policy_violation': 9},
                description="No password policy is set",
                recommendation="Configure account password policy"
            )

    async def _scan_password_policy(self, iam) -> None:
        """Check password policy settings"""
        try:
            policy = iam.get_account_password_policy()['PasswordPolicy']

            if not all([
                policy.get('MinimumPasswordLength', 0) >= 14,
                policy.get('RequireSymbols'),
                policy.get('RequireNumbers'),
                policy.get('RequireUppercaseCharacters'),
                policy.get('RequireLowercaseCharacters'),
                policy.get('MaxPasswordAge', 0) <= 90,
                policy.get('PasswordReusePrevention', 0) >= 24
            ]):
                risk_factors = {
                    'password_policy': 9,
                    'access_control': 8
                }

                self.add_finding(
                    service="IAM",
                    resource="PasswordPolicy",
                    risk_factors=risk_factors,
                    description="Password policy does not meet security requirements",
                    recommendation="Strengthen password policy settings",
                    details={"current_policy": policy}
                )
        except iam.exceptions.NoSuchEntityException:
            self.add_finding(
                service="IAM",
                resource="PasswordPolicy",
                risk_factors={"password_policy": 10},
                description="No password policy is set",
                recommendation="Configure a strong password policy"
            )

     async def _scan_root_account(self, iam) -> None:
        """Check root account usage"""
        try:
            credential_report = iam.get_credential_report()['Content']
            root_user = next(user for user in credential_report if user['user'] == '<root_account>')

            if root_user['access_key_1_active'] or root_user['access_key_2_active']:
                risk_factors = {
                    'root_account': 10,
                    'security_best_practice': 9
                }

                self.add_finding(
                    service="IAM",
                    resource="RootAccount",
                    risk_factors=risk_factors,
                    description="Root account has active access keys",
                    recommendation="Remove root account access keys"
                )
        except Exception as e:
            self.logger.error(f"Failed to check root account: {str(e)}")

    async def _scan_access_keys(self) -> None:
        """Check access key rotation and usage"""
        iam = self.session.client('iam')
        users = await self._get_all_users(iam)

        for user in users:
            access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']

            for key in access_keys:
                key_details = self._get_access_key_last_used(iam, key['AccessKeyId'])

                if self._is_access_key_old(key['CreateDate']):
                    risk_factors = {
                        'credential_exposure': 7,
                        'policy_violation': 5
                    }

                    self.add_finding(
                        service="IAM",
                        resource=f"AccessKey/{user['UserName']}/{key['AccessKeyId']}",
                        risk_factors=risk_factors,
                        description=f"Access key for user {user['UserName']} is older than 90 days",
                        recommendation="Rotate access keys regularly",
                        details={"last_used": key_details}
                    )

    async def _scan_roles(self) -> None:
        """Scan IAM roles for security issues"""
        iam = self.session.client('iam')
        roles = await self._get_all_roles(iam)

        for role in roles:
            # Check role policies
            policies = iam.list_role_policies(RoleName=role['RoleName'])['PolicyNames']
            attached_policies = iam.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']

            # Check trust relationships
            trust_policy = role['AssumeRolePolicyDocument']
            if self._has_risky_trust_relationship(trust_policy):
                risk_factors = {
                    'privilege_escalation': 8,
                    'misconfiguration': 6
                }

                self.add_finding(
                    service="IAM",
                    resource=f"Role/{role['RoleName']}",
                    risk_factors=risk_factors,
                    description=f"Role {role['RoleName']} has potentially risky trust relationship",
                    recommendation="Review and restrict trust relationship",
                    details={"trust_policy": trust_policy}
                )

    async def _scan_users(self) -> None:
        """Scan IAM users for security issues"""
        iam = self.session.client('iam')
        users = await self._get_all_users(iam)

        for user in users:
            # Check for console access without MFA
            login_profile = self._has_console_access(iam, user['UserName'])
            if login_profile and not self._has_mfa_enabled(iam, user['UserName']):
                risk_factors = {
                    'weak_authentication': 9,
                    'policy_violation': 7
                }

                self.add_finding(
                    service="IAM",
                    resource=f"User/{user['UserName']}",
                    risk_factors=risk_factors,
                    description=f"User {user['UserName']} has console access without MFA",
                    recommendation="Enable MFA for all users with console access"
                )

            # Check for direct policy attachments
            attached_policies = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
            if attached_policies:
                risk_factors = {
                    'policy_violation': 5,
                    'misconfiguration': 4
                }

                self.add_finding(
                    service="IAM",
                    resource=f"User/{user['UserName']}",
                    risk_factors=risk_factors,
                    description=f"User {user['UserName']} has directly attached policies",
                    recommendation="Use groups for policy management",
                    details={"attached_policies": attached_policies}
                )

    async def _scan_policies(self) -> None:
        """Scan IAM policies for security issues"""
        iam = self.session.client('iam')
        policies = await self._get_all_policies(iam)

        for policy in policies:
            if policy['IsAttachable']:
                # Get policy versions
                policy_versions = iam.list_policy_versions(PolicyArn=policy['Arn'])['Versions']
                current_version = next(v for v in policy_versions if v['IsDefaultVersion'])

                # Get policy document
                policy_document = iam.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=current_version['VersionId']
                )['PolicyVersion']['Document']

                if self._has_risky_permissions(policy_document):
                    risk_factors = {
                        'privilege_escalation': 8,
                        'misconfiguration': 6
                    }

                    self.add_finding(
                        service="IAM",
                        resource=f"Policy/{policy['PolicyName']}",
                        risk_factors=risk_factors,
                        description=f"Policy {policy['PolicyName']} contains risky permissions",
                        recommendation="Review and restrict policy permissions",
                        details={"policy_document": policy_document}
                    )

    async def _get_all_users(self, iam) -> List[Dict[str, Any]]:
        """Get all IAM users"""
        users = []
        paginator = iam.get_paginator('list_users')
        async for page in paginator.paginate():
            users.extend(page['Users'])
        return users

    async def _get_all_roles(self, iam) -> List[Dict[str, Any]]:
        """Get all IAM roles"""
        roles = []
        paginator = iam.get_paginator('list_roles')
        async for page in paginator.paginate():
            roles.extend(page['Roles'])
        return roles

    async def _get_all_policies(self, iam) -> List[Dict[str, Any]]:
        """Get all IAM policies"""
        policies = []
        paginator = iam.get_paginator('list_policies')
        async for page in paginator.paginate(Scope='Local'):
            policies.extend(page['Policies'])
        return policies

    def _get_access_key_last_used(self, iam, access_key_id: str) -> Dict[str, Any]:
        """Get access key last usage details"""
        try:
            return iam.get_access_key_last_used(AccessKeyId=access_key_id)['AccessKeyLastUsed']
        except Exception:
            return {"LastUsedDate": None}

    def _is_access_key_old(self, create_date) -> bool:
        """Check if access key is older than 90 days"""
        from datetime import datetime, timezone
        age = (datetime.now(timezone.utc) - create_date).days
        return age > 90

    def _has_risky_trust_relationship(self, trust_policy: Dict) -> bool:
        """Check for risky trust relationships"""
        if isinstance(trust_policy, str):
            trust_policy = json.loads(trust_policy)

        for statement in trust_policy.get('Statement', []):
            principal = statement.get('Principal', {})
            if principal == "*" or \
               principal.get('AWS') == "*" or \
               principal.get('Federated') == "*":
                return True
        return False

    def _has_console_access(self, iam, username: str) -> bool:
        """Check if user has console access"""
        try:
            iam.get_login_profile(UserName=username)
            return True
        except iam.exceptions.NoSuchEntityException:
            return False

    async def _scan_inactive_users(self, iam) -> None:
        """Check for inactive users"""
        credential_report = iam.get_credential_report()['Content']

        for user in credential_report:
            if user['password_enabled'] and user['password_last_used']:
                last_used = (self.scan_time - user['password_last_used']).days
                if last_used > 90:
                    risk_factors = {
                        'account_management': 6,
                        'access_control': 5
                    }

                    self.add_finding(
                        service="IAM",
                        resource=f"User/{user['user']}",
                        risk_factors=risk_factors,
                        description=f"User account inactive for {last_used} days",
                        recommendation="Review and disable inactive user accounts"
                    )

    async def _scan_policy_attachments(self, iam) -> None:
        """Check policy attachments"""
        policies = []
        paginator = iam.get_paginator('list_policies')
        async for page in paginator.paginate(Scope='Local'):
            policies.extend(page['Policies'])

        for policy in policies:
            if self._is_policy_overly_permissive(iam, policy['Arn']):
                risk_factors = {
                    'policy': 8,
                    'privilege_management': 7
                }

                self.add_finding(
                    service="IAM",
                    resource=f"Policy/{policy['PolicyName']}",
                    risk_factors=risk_factors,
                    description="Policy has overly permissive permissions",
                    recommendation="Review and restrict policy permissions"
                )

    def _is_policy_overly_permissive(self, iam, policy_arn: str) -> bool:
        """Check if policy is overly permissive"""
        try:
            policy_version = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            )['PolicyVersion']

            for statement in policy_version['Document']['Statement']:
                if statement['Effect'] == 'Allow' and '*' in statement.get('Action', []):
                    return True

            return False
        except Exception:
            return False

    def _has_mfa_enabled(self, iam, username: str) -> bool:
        """Check if user has MFA enabled"""
        try:
            mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
            return len(mfa_devices) > 0
        except Exception:
            return False
    async def _scan_mfa_usage(self, iam) -> None:
        """Check MFA usage"""
        users = []
        paginator = iam.get_paginator('list_users')
        async for page in paginator.paginate():
            users.extend(page['Users'])

        for user in users:
            mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']

            if not mfa_devices:
                risk_factors = {
                    'mfa': 8,
                    'authentication': 7
                }

                self.add_finding(
                    service="IAM",
                    resource=f"User/{user['UserName']}",
                    risk_factors=risk_factors,
                    description="User does not have MFA enabled",
                    recommendation="Enable MFA for all IAM users"
                )

    def _has_risky_permissions(self, policy_document: Dict) -> bool:
        """Check for risky permissions in policy"""
        if isinstance(policy_document, str):
            policy_document = json.loads(policy_document)

        risky_actions = [
            "*",
            "iam:*",
            "s3:*",
            "ec2:*",
            "lambda:*",
            "dynamodb:*"
        ]

        for statement in policy_document.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]

                if any(action in risky_actions for action in actions):
                    return True

        return False
