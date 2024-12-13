# aws_security_scanner/core/utils.py
import asyncio
import logging
from typing import List, Dict, Any, Callable
import boto3
from botocore.exceptions import ClientError

class AWSUtils:
    """Utility functions for AWS operations"""

    @staticmethod
    async def paginate(
        operation: Callable,
        key: str,
        **kwargs
    ) -> List[Any]:
        """Asynchronous pagination helper"""
        results = []
        paginator = operation.get_paginator(key)

        async for page in paginator.paginate(**kwargs):
            results.extend(page.get(key, []))

        return results

    @staticmethod
    def get_aws_session(
        profile: str = None,
        region: str = None,
        role_arn: str = None
    ) -> boto3.Session:
        """Create AWS session with optional role assumption"""
        try:
            if role_arn:
                sts = boto3.client('sts')
                response = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName='SecurityScan'
                )
                credentials = response['Credentials']

                return boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    region_name=region,
                    profile_name=profile
                )
            else:
                return boto3.Session(
                    profile_name=profile,
                    region_name=region
                )
        except Exception as e:
            logging.error(f"Failed to create AWS session: {str(e)}")
            raise

class RateLimiter:
    """Rate limiter for AWS API calls"""

    def __init__(self, calls_per_second: int = 5):
        self.calls_per_second = calls_per_second
        self.minimum_interval = 1.0 / calls_per_second
        self.last_call_time = 0.0
        self.lock = asyncio.Lock()

    async def acquire(self):
        """Acquire rate limit slot"""
        async with self.lock:
            current_time = asyncio.get_event_loop().time()
            time_since_last_call = current_time - self.last_call_time

            if time_since_last_call < self.minimum_interval:
                delay = self.minimum_interval - time_since_last_call
                await asyncio.sleep(delay)

            self.last_call_time = asyncio.get_event_loop().time()

class ResourceTagger:
    """Utility for tagging AWS resources"""

    def __init__(self, session: boto3.Session):
        self.session = session

    async def tag_resource(
        self,
        resource_arn: str,
        tags: Dict[str, str]
    ) -> bool:
        """Tag AWS resource"""
        try:
            client = self.session.client('resourcegroupstaggingapi')
            await client.tag_resources(
                ResourceARNList=[resource_arn],
                Tags=tags
            )
            return True
        except ClientError as e:
            logging.error(f"Failed to tag resource {resource_arn}: {str(e)}")
            return False

class MetricsCollector:
    """Collect and track scanner metrics"""

    def __init__(self):
        self.metrics: Dict[str, Any] = {
            "scan_count": 0,
            "total_findings": 0,
            "risk_levels": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0
            },
            "service_findings": {},
            "scan_duration": []
        }

    def update_metrics(self, findings: List[Dict[str, Any]], duration: float):
        """Update metrics with new scan results"""
        self.metrics["scan_count"] += 1
        self.metrics["total_findings"] += len(findings)
        self.metrics["scan_duration"].append(duration)

        for finding in findings:
            # Update risk level counts
            self.metrics["risk_levels"][finding["risk_level"]] += 1

            # Update service-specific counts
            service = finding["service"]
            if service not in self.metrics["service_findings"]:
                self.metrics["service_findings"][service] = 0
            self.metrics["service_findings"][service] += 1

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of collected metrics"""
        return {
            "total_scans": self.metrics["scan_count"],
            "total_findings": self.metrics["total_findings"],
            "risk_distribution": self.metrics["risk_levels"],
            "service_distribution": self.metrics["service_findings"],
            "average_duration": sum(self.metrics["scan_duration"]) / len(self.metrics["scan_duration"])
            if self.metrics["scan_duration"] else 0
        }
