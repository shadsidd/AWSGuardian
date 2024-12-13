# notifiers/slack.py
import json
import requests
from typing import Dict, List, Any
from .base import BaseNotifier
from ..models.finding import Finding
from ..utils.exceptions import NotificationError

class SlackNotifier(BaseNotifier):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config['webhook_url']
        self.channel = config.get('channel')
        self.username = config.get('username', 'AWS Security Monitor')
        self.icon_emoji = config.get('icon_emoji', ':shield:')

    def send(self, findings: List[Finding], context: Dict[str, Any] = None) -> bool:
        try:
            if not self.should_notify(findings):
                return False

            message = self.format_message(findings, context)
            response = requests.post(
                self.webhook_url,
                json=message,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            return True

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error sending Slack notification: {str(e)}")
            raise NotificationError(f"Failed to send Slack notification: {str(e)}")

    def format_message(self, findings: List[Finding], context: Dict[str, Any] = None) -> Dict:
        blocks = []

        # Header
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 Security Scan Results 🚨",
                "emoji": True
            }
        })

        # Summary
        summary = self._create_summary_block(findings)
        blocks.append(summary)

        # Critical Findings
        critical_findings = [f for f in findings if f.risk_level == 'CRITICAL']
        if critical_findings:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Critical Findings:*"
                }
            })
            blocks.extend(self._format_findings_blocks(critical_findings))

        # Action Buttons
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View Full Report",
                        "emoji": True
                    },
                    "url": context.get('report_url', '#') if context else '#',
                    "style": "primary"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Acknowledge All",
                        "emoji": True
                    },
                    "style": "danger"
                }
            ]
        })

        return {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "blocks": blocks
        }

    def _create_summary_block(self, findings: List[Finding]) -> Dict:
        critical_count = sum(1 for f in findings if f.risk_level == 'CRITICAL')
        high_count = sum(1 for f in findings if f.risk_level == 'HIGH')
        medium_count = sum(1 for f in findings if f.risk_level == 'MEDIUM')
        low_count = sum(1 for f in findings if f.risk_level == 'LOW')

        return {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Scan Summary*\n"
                       f"🔴 Critical: {critical_count}\n"
                       f"🟠 High: {high_count}\n"
                       f"🟡 Medium: {medium_count}\n"
                       f"🟢 Low: {low_count}"
            }
        }

    def _format_findings_blocks(self, findings: List[Finding]) -> List[Dict]:
        blocks = []
        for finding in findings:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Resource:* `{finding.resource_id}`\n"
                        f"*Issue:* {finding.description}\n"
                        f"*Impact:* {finding.details.get('impact', 'N/A')}"
                    )
                }
            })
        return blocks
