# notifiers/notification_manager.py
from typing import Dict, List, Any
from .base import BaseNotifier
from .slack import SlackNotifier
from .email import EmailNotifier
from ..models.finding import Finding
from ..utils.logger import get_logger
from ..utils.exceptions import NotificationError

class NotificationManager:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(__name__)
        self.notifiers = self._initialize_notifiers()

    def _initialize_notifiers(self) -> Dict[str, BaseNotifier]:
        notifiers = {}
        notification_config = self.config.get('notifications', {})

        if notification_config.get('slack', {}).get('enabled', False):
            notifiers['slack'] = SlackNotifier(notification_config['slack'])

        if notification_config.get('email', {}).get('enabled', False):
            notifiers['email'] = EmailNotifier(notification_config['email'])

        return notifiers

    def send_notifications(
        self,
        findings: List[Finding],
        context: Dict[str, Any] = None
    ) -> Dict[str, bool]:
        results = {}

        for notifier_name, notifier in self.notifiers.items():
            try:
                results[notifier_name] = notifier.send(findings, context)
            except NotificationError as e:
                self.logger.error(
                    f"Error sending notification via {notifier_name}: {str(e)}"
                )
                results[notifier_name] = False

        return results

    def send_critical_alert(
        self,
        finding: Finding,
        context: Dict[str, Any] = None
    ) -> Dict[str, bool]:
        """Send immediate alert for critical findings"""
        return self.send_notifications([finding], {
            **(context or {}),
            'priority': 'critical',
            'immediate': True
        })
