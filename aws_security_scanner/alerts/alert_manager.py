
# aws_security_scanner/alerts/alert_manager.py
from typing import List, Dict, Any, Type
from ..core.findings import Finding
from .alert_rules import AlertRule
from .notification_manager import NotificationManager
import logging
import asyncio

class AlertManager:
    """Manages security alerts and notifications"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.notification_manager = NotificationManager(config)
        self.rules: List[AlertRule] = []
        self.logger = logging.getLogger(__name__)
        self._load_rules()

    def _load_rules(self) -> None:
        """Load alert rules from configuration"""
        try:
            for rule_config in self.config.get('alert_rules', []):
                rule_type = rule_config.get('type')
                if rule_type in RULE_TYPES:
                    rule = RULE_TYPES[rule_type](rule_config)
                    self.rules.append(rule)
        except Exception as e:
            self.logger.error(f"Failed to load alert rules: {str(e)}")
            raise

    async def process_findings(self, findings: List[Finding]) -> None:
        """Process findings and generate alerts"""
        try:
            alerts = []
            for rule in self.rules:
                matched_findings = rule.evaluate(findings)
                if matched_findings:
                    alert = self._create_alert(rule, matched_findings)
                    alerts.append(alert)

            if alerts:
                await self._send_alerts(alerts)
        except Exception as e:
            self.logger.error(f"Failed to process findings: {str(e)}")
            raise

    def _create_alert(self, rule: AlertRule, findings: List[Finding]) -> Dict[str, Any]:
        """Create alert from findings"""
        return {
            'rule_name': rule.name,
            'severity': rule.severity,
            'findings': [finding.to_dict() for finding in findings],
            'timestamp': datetime.utcnow().isoformat(),
            'alert_id': str(uuid.uuid4()),
            'context': self._get_alert_context(findings)
        }

    async def _send_alerts(self, alerts: List[Dict[str, Any]]) -> None:
        """Send alerts through configured channels"""
        try:
            tasks = []
            for alert in alerts:
                tasks.extend([
                    self.notification_manager.send_slack_alert(alert),
                    self.notification_manager.send_email_alert(alert),
                    self.notification_manager.send_sns_alert(alert),
                    self.notification_manager.create_security_hub_finding(alert)
                ])

            await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"Failed to send alerts: {str(e)}")
            raise

    def _get_alert_context(self, findings: List[Finding]) -> Dict[str, Any]:
        """Get additional context for alert"""
        return {
            'affected_services': list(set(f.service for f in findings)),
            'risk_levels': self._summarize_risk_levels(findings),
            'resource_count': len(set(f.resource for f in findings)),
            'recommendations': self._aggregate_recommendations(findings)
        }

    @staticmethod
    def _summarize_risk_levels(findings: List[Finding]) -> Dict[str, int]:
        """Summarize risk levels of findings"""
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            max_risk = max(finding.risk_factors.values())
            if max_risk >= 9:
                summary['critical'] += 1
            elif max_risk >= 7:
                summary['high'] += 1
            elif max_risk >= 4:
                summary['medium'] += 1
            else:
                summary['low'] += 1
        return summary

    @staticmethod
    def _aggregate_recommendations(findings: List[Finding]) -> List[str]:
        """Aggregate unique recommendations"""
        return list(set(f.recommendation for f in findings))
