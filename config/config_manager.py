# aws_security_scanner/config/config_manager.py
from typing import Dict, Any, Optional
import yaml
import json
import os
from pathlib import Path
from .validators import ConfigValidator
from .exceptions import ConfigurationError
import logging
from typing import Union

class ConfigManager:
    """Manages scanner configuration and settings"""

    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.validator = ConfigValidator()
        self.config: Dict[str, Any] = {}
        self.config_path = config_path or self._get_default_config_path()
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from file"""
        try:
            config_data = self._read_config_file()
            merged_config = self._merge_with_defaults(config_data)
            self.validator.validate(merged_config)
            self.config = merged_config
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {str(e)}")

    def get_scanner_config(self, scanner_name: str) -> Dict[str, Any]:
        """Get configuration for specific scanner"""
        return self.config.get('scanners', {}).get(scanner_name, {})

    def get_alert_config(self) -> Dict[str, Any]:
        """Get alert system configuration"""
        return self.config.get('alerts', {})

    def get_notification_config(self) -> Dict[str, Any]:
        """Get notification configuration"""
        return self.config.get('notifications', {})

    def update_config(self, new_config: Dict[str, Any], validate: bool = True) -> None:
        """Update configuration"""
        if validate:
            self.validator.validate(new_config)
        self.config.update(new_config)
        self._save_config()

    def _read_config_file(self) -> Dict[str, Any]:
        """Read configuration file"""
        if not os.path.exists(self.config_path):
            self.logger.warning(f"Config file not found at {self.config_path}, using defaults")
            return {}

        file_ext = Path(self.config_path).suffix.lower()
        with open(self.config_path, 'r') as f:
            if file_ext == '.yaml' or file_ext == '.yml':
                return yaml.safe_load(f)
            elif file_ext == '.json':
                return json.load(f)
            else:
                raise ConfigurationError(f"Unsupported config file format: {file_ext}")

    def _save_config(self) -> None:
        """Save current configuration to file"""
        try:
            file_ext = Path(self.config_path).suffix.lower()
            with open(self.config_path, 'w') as f:
                if file_ext == '.yaml' or file_ext == '.yml':
                    yaml.safe_dump(self.config, f)
                elif file_ext == '.json':
                    json.dump(self.config, f, indent=2)
        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration: {str(e)}")

    def _merge_with_defaults(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge configuration with defaults"""
        return {**self.get_default_config(), **config}

    @staticmethod
    def _get_default_config_path() -> str:
        """Get default configuration file path"""
        config_paths = [
            os.environ.get('AWS_SECURITY_SCANNER_CONFIG'),
            os.path.expanduser('~/.aws-security-scanner/config.yaml'),
            '/etc/aws-security-scanner/config.yaml'
        ]

        for path in config_paths:
            if path and os.path.exists(path):
                return path

        return os.path.expanduser('~/.aws-security-scanner/config.yaml')

    @staticmethod
    def get_default_config() -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'scanners': {
                'enabled_scanners': [
                    'iam', 's3', 'ec2', 'rds', 'cloudfront',
                    'redshift', 'lambda', 'apigateway'
                ],
                'scan_interval': 3600,
                'parallel_scans': 3,
                'timeout': 300
            },
            'alerts': {
                'enabled': True,
                'alert_rules': [
                    {
                        'name': 'Critical Risk Alert',
                        'type': 'risk_based',
                        'severity': 'critical',
                        'risk_threshold': 9
                    },
                    {
                        'name': 'Compliance Alert',
                        'type': 'compliance',
                        'severity': 'high',
                        'frameworks': ['PCI-DSS', 'HIPAA', 'SOC2']
                    }
                ]
            },
            'notifications': {
                'slack': {
                    'enabled': False,
                    'webhook_url': '',
                    'channel': '#security-alerts'
                },
                'email': {
                    'enabled': False,
                    'sender': '',
                    'recipients': [],
                    'ses_region': 'us-east-1'
                },
                'sns': {
                    'enabled': False,
                    'topic_arn': ''
                },
                'security_hub': {
                    'enabled': False,
                    'region': 'us-east-1'
                }
            },
            'reporting': {
                'enabled': True,
                'formats': ['json', 'html', 'csv'],
                'output_dir': './reports',
                'retention_days': 90
            },
            'aws': {
                'regions': ['us-east-1'],
                'role_arn': '',
                'external_id': '',
                'session_duration': 3600
            },
            'logging': {
                'level': 'INFO',
                'file': './aws-security-scanner.log',
                'max_size': 10485760,  # 10MB
                'backup_count': 5
            }
        }
