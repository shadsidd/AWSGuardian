# utils/rate_limiter.py
import time
import boto3
from typing import Dict, Callable
from functools import wraps
import threading
from datetime import datetime, timedelta

class AWSRateLimiter:
    # Default API limits per service
    DEFAULT_LIMITS = {
        'ec2': {'calls_per_second': 50},
        's3': {'calls_per_second': 100},
        'rds': {'calls_per_second': 40},
        'iam': {'calls_per_second': 15}
    }

    def __init__(self):
        self.calls = {}
        self.locks = {}
        self._initialize_tracking()

    def _initialize_tracking(self):
        for service in self.DEFAULT_LIMITS:
            self.calls[service] = []
            self.locks[service] = threading.Lock()

    def wait_if_needed(self, service: str):
        with self.locks[service]:
            current_time = datetime.now()
            # Remove old calls
            self.calls[service] = [
                call_time for call_time in self.calls[service]
                if current_time - call_time < timedelta(seconds=1)
            ]

            # Check if we need to wait
            limit = self.DEFAULT_LIMITS[service]['calls_per_second']
            if len(self.calls[service]) >= limit:
                sleep_time = 1 - (current_time - min(self.calls[service])).total_seconds()
                if sleep_time > 0:
                    time.sleep(sleep_time)

            # Add current call
            self.calls[service].append(current_time)

def rate_limited(service: str):
    rate_limiter = AWSRateLimiter()

    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            rate_limiter.wait_if_needed(service)
            return func(*args, **kwargs)
        return wrapper
    return decorator

# schedulers/aws_scheduler.py
import boto3
from datetime import datetime, timedelta
from typing import Dict, Any
import json

class AWSScheduler:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.events_client = boto3.client('events')
        self.lambda_client = boto3.client('lambda')

    def schedule_scan(self, schedule_expression: str, scan_config: Dict[str, Any]):
        """
        Schedule scans using AWS EventBridge (CloudWatch Events)
        """
        # Create or update Lambda function
        function_arn = self._ensure_lambda_function()

        # Create EventBridge rule
        rule_name = f"aws-exposure-monitor-{datetime.now().strftime('%Y%m%d')}"

        try:
            self.events_client.put_rule(
                Name=rule_name,
                ScheduleExpression=schedule_expression,
                State='ENABLED',
                Description='AWS Resource Exposure Monitor scheduled scan'
            )

            # Add Lambda permission
            self._ensure_lambda_permission(rule_name, function_arn)

            # Add target to rule
            self.events_client.put_targets(
                Rule=rule_name,
                Targets=[{
                    'Id': 'ScanTarget',
                    'Arn': function_arn,
                    'Input': json.dumps(scan_config)
                }]
            )

            return rule_name
        except Exception as e:
            raise SchedulerError(f"Failed to schedule scan: {str(e)}")

    def _ensure_lambda_function(self) -> str:
        """
        Ensure Lambda function exists for scanning
        """
        function_name = 'aws-exposure-monitor'

        try:
            response = self.lambda_client.get_function(
                FunctionName=function_name
            )
            return response['Configuration']['FunctionArn']
        except self.lambda_client.exceptions.ResourceNotFoundException:
            # Create new function
            return self._create_lambda_function(function_name)

    def _create_lambda_function(self, function_name: str) -> str:
        """
        Create Lambda function for scanning
        """
        with open('lambda_function.zip', 'rb') as f:
            zip_bytes = f.read()

        response = self.lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.9',
            Role=self.config['lambda_role_arn'],
            Handler='main.lambda_handler',
            Code={'ZipFile': zip_bytes},
            Timeout=900,  # 15 minutes
            MemorySize=1024,
            Environment={
                'Variables': {
                    'CONFIG_BUCKET': self.config['config_bucket'],
                    'CONFIG_KEY': self.config['config_key']
                }
            },
            Tags={
                'Service': 'aws-exposure-monitor',
                'Environment': self.config['environment']
            }
        )

        return response['FunctionArn']
