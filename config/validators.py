# aws_security_scanner/config/validators.py
from typing import Dict, Any, List
from .exceptions import ConfigurationError
import jsonschema

class ConfigValidator:
    """Validates scanner configuration"""

    def __init__(self):
        self.schema = self._get_config_schema()

    def validate(self, config: Dict[str, Any]) -> None:
        """Validate configuration against schema"""
        try:
            jsonschema.validate(instance=config, schema=self.schema)
            self._validate_custom_rules(config)
        except jsonschema.exceptions.ValidationError as e:
            raise ConfigurationError(f"Configuration validation failed: {str(e)}")

    def _validate_custom_rules(self, config: Dict[str, Any]) -> None:
        """Perform custom validation rules"""
        self._validate_aws_config(config.get('aws', {}))
        self._validate_notification_config(config.get('notifications', {}))
        self._validate_scanner_config(config.get('scanners', {}))
        self._validate_alert_rules(config.get('alerts', {}).get('alert_rules', []))

    def _validate_aws_config(self, aws_config: Dict[str, Any]) -> None:
        """Validate AWS configuration"""
        if aws_config.get('role_arn') and not aws_config.get('external_id'):
            self.logger.warning("Role ARN specified without external ID")

        if aws_config.get('regions'):
            invalid_regions = [
                region for region in aws_config['regions']
                if not self._is_valid_aws_region(region)
            ]
            if invalid_regions:
                raise ConfigurationError(f"Invalid AWS regions: {invalid_regions}")

    def _validate_notification_config(self, notification_config: Dict[str, Any]) -> None:
        """Validate notification configuration"""
        if notification_config.get('slack', {}).get('enabled'):
            if not notification_config['slack'].get('webhook_url'):
                raise ConfigurationError("Slack notifications enabled but webhook URL not provided")

        if notification_config.get('email', {}).get('enabled'):
            email_config = notification_config['email']
            if not email_config.get('sender') or not email_config.get('recipients'):
                raise ConfigurationError("Email notifications enabled but sender or recipients not provided")

    def _validate_scanner_config(self, scanner_config: Dict[str, Any]) -> None:
        """Validate scanner configuration"""
        if scanner_config.get('parallel_scans', 1) > 5:
            self.logger.warning("High number of parallel scans may impact performance")

        invalid_scanners = [
            scanner for scanner in scanner_config.get('enabled_scanners', [])
            if not self._is_valid_scanner(scanner)
        ]
        if invalid_scanners:
            raise ConfigurationError(f"Invalid scanner types: {invalid_scanners}")

    def _validate_alert_rules(self, rules: List[Dict[str, Any]]) -> None:
        """Validate alert rules configuration"""
        for rule in rules:
            if rule['type'] not in ['risk_based', 'compliance', 'custom']:
                raise ConfigurationError(f"Invalid alert rule type: {rule['type']}")

            if rule['type'] == 'risk_based' and not isinstance(
                rule.get('risk_threshold', 0), (int, float)
            ):
                raise ConfigurationError("Risk threshold must be a number")

    @staticmethod
    def _is_valid_aws_region(region: str) -> bool:
        """Check if AWS region is valid"""
        # This is a simplified check - in production, maintain a current list of regions
        return region.startswith(('us-', 'eu-', 'ap-', 'sa-', 'ca-', 'me-', 'af-'))

    @staticmethod
    def _is_valid_scanner(scanner: str) -> bool:
        """Check if scanner type is valid"""
        valid_scanners = {
            'iam', 's3', 'ec2', 'rds', 'cloudfront', 'redshift',
            'lambda', 'apigateway', 'eks', 'cloudtrail', 'config'
        }
        return scanner in valid_scanners

    @staticmethod
    def _get_config_schema() -> Dict[str, Any]:
        """Get JSON schema for configuration validation"""
        return {
            "type": "object",
            "properties": {
                "scanners": {
                    "type": "object",
                    "properties": {
                        "enabled_scanners": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "scan_interval": {"type": "number"},
                        "parallel_scans": {"type": "number"},
                        "timeout": {"type": "number"}
                    }
                },
                "alerts": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "alert_rules": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["name", "type", "severity"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "type": {"type": "string"},
                                    "severity": {"type": "string"}
                                }
                            }
                        }
                    }
                },
                "notifications": {
                    "type": "object",
                    "properties": {
                        "slack": {"type": "object"},
                        "email": {"type": "object"},
                        "sns": {"type": "object"},
                        "security_hub": {"type": "object"}
                    }
                },
                "aws": {
                    "type": "object",
                    "properties": {
                        "regions": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "role_arn": {"type": "string"},
                        "external_id": {"type": "string"},
                        "session_duration": {"type": "number"}
                    }
                }
            }
        }

# aws_security_scanner/config/exceptions.py
class ConfigurationError(Exception):
    """Exception raised for configuration errors"""
    pass
