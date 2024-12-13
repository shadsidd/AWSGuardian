# notifiers/base.py
from abc import ABC, abstractmethod
from typing import Dict, List, Any
from ..models.finding import Finding
from ..utils.logger import get_logger

class BaseNotifier(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(__name__)

    @abstractmethod
    def send(self, findings: List[Finding], context: Dict[str, Any] = None) -> bool:
        """Send notification with findings"""
        pass

    @abstractmethod
    def format_message(self, findings: List[Finding], context: Dict[str, Any] = None) -> str:
        """Format findings into a message"""
        pass

    def should_notify(self, findings: List[Finding]) -> bool:
        """Determine if notification should be sent based on thresholds"""
        if not findings:
            return False

        thresholds = self.config.get('thresholds', {})
        critical_count = sum(1 for f in findings if f.risk_level == 'CRITICAL')
        high_count = sum(1 for f in findings if f.risk_level == 'HIGH')
        medium_count = sum(1 for f in findings if f.risk_level == 'MEDIUM')

        return (
            critical_count >= thresholds.get('critical', 1) or
            high_count >= thresholds.get('high', 5) or
            medium_count >= thresholds.get('medium', 10)
        )
