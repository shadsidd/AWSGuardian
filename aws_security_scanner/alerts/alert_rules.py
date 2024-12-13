# aws_security_scanner/alerts/alert_rules.py
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from ..core.findings import Finding

class AlertRule(ABC):
    """Base class for alert rules"""

    def __init__(self, config: Dict[str, Any]):
        self.name = config['name']
        self.severity = config['severity']
        self.config = config

    @abstractmethod
    def evaluate(self, findings: List[Finding]) -> List[Finding]:
        """Evaluate findings against the rule"""
        pass

class RiskBasedRule(AlertRule):
    """Alert rule based on risk factors"""

    def evaluate(self, findings: List[Finding]) -> List[Finding]:
        """Evaluate findings based on risk levels"""
        threshold = self.config.get('risk_threshold', 7)
        return [
            finding for finding in findings
            if max(finding.risk_factors.values()) >= threshold
        ]

class ComplianceRule(AlertRule):
    """Alert rule for compliance violations"""

    def evaluate(self, findings: List[Finding]) -> List[Finding]:
        """Evaluate findings for compliance violations"""
        compliance_frameworks = self.config.get('frameworks', [])
        return [
            finding for finding in findings
            if any(framework in finding.compliance_impact
                  for framework in compliance_frameworks)
        ]

class CustomRule(AlertRule):
    """Custom alert rule with configurable conditions"""

    def evaluate(self, findings: List[Finding]) -> List[Finding]:
        """Evaluate findings against custom conditions"""
        conditions = self.config.get('conditions', {})
        return [
            finding for finding in findings
            if self._matches_conditions(finding, conditions)
        ]

    def _matches_conditions(self, finding: Finding, conditions: Dict[str, Any]) -> bool:
        """Check if finding matches custom conditions"""
        for field, value in conditions.items():
            if field == 'service' and finding.service != value:
                return False
            elif field == 'resource_type' and finding.resource.split('/')[0] != value:
                return False
            elif field == 'min_risk_score' and max(finding.risk_factors.values()) < value:
                return False
            # Add more condition types as needed
        return True

# Register rule types
RULE_TYPES = {
    'risk_based': RiskBasedRule,
    'compliance': ComplianceRule,
    'custom': CustomRule
}
