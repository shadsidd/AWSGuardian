# utils/aws_utils.py
import boto3
from typing import List, Optional
from .logger import get_logger

logger = get_logger(__name__)

# Preserve existing functions
def get_boto3_client(service_name: str, region: str = None) -> boto3.client:
    """Original function to get boto3 client"""
    session = boto3.Session(region_name=region) if region else boto3.Session()
    return session.client(service_name)

def get_boto3_resource(service_name: str, region: str = None) -> boto3.resource:
    """Original function to get boto3 resource"""
    session = boto3.Session(region_name=region) if region else boto3.Session()
    return session.resource(service_name)

# Add new organization-related functions
def create_session(account_id: Optional[str] = None,
                  role_name: str = 'OrganizationAccountAccessRole',
                  region: Optional[str] = None) -> boto3.Session:
    """Create boto3 session, optionally for a different account"""
    try:
        if not account_id:
            return boto3.Session(region_name=region)

        sts = boto3.client('sts')
        role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'

        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='ResourceExposureMonitor'
        )
        credentials = response['Credentials']
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region
        )
    except Exception as e:
        logger.error(f"Failed to create session for account {account_id}: {str(e)}")
        raise

def get_organization_accounts(excluded_accounts: List[str] = None) -> List[str]:
    """Get list of active accounts in organization"""
    try:
        org_client = get_boto3_client('organizations')
        accounts = []
        paginator = org_client.get_paginator('list_accounts')

        excluded_accounts = excluded_accounts or []

        for page in paginator.paginate():
            for account in page['Accounts']:
                if (account['Status'] == 'ACTIVE' and
                    account['Id'] not in excluded_accounts):
                    accounts.append(account['Id'])

        return accounts
    except Exception as e:
        logger.error(f"Failed to list organization accounts: {str(e)}")
        raise

def get_current_account() -> str:
    """Get current AWS account ID"""
    try:
        sts = get_boto3_client('sts')
        return sts.get_caller_identity()['Account']
    except Exception as e:
        logger.error(f"Failed to get current account ID: {str(e)}")
        raise

# Helper function to maintain existing client/resource creation pattern
def get_session_client(session: boto3.Session, service_name: str) -> boto3.client:
    """Get client from specific session"""
    return session.client(service_name)

def get_session_resource(session: boto3.Session, service_name: str) -> boto3.resource:
    """Get resource from specific session"""
    return session.resource(service_name)
