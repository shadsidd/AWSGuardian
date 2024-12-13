# aws_security_scanner/alerts/notification_manager.py
from typing import Dict, Any
import boto3
import aiohttp
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class NotificationManager:
    """Manages different notification channels"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = boto3.Session()
        self._init_clients()

    def _init_clients(self) -> None:
        """Initialize AWS clients"""
        self.sns = self.session.client('sns')
        self.ses = self.session.client('ses')
        self.securityhub = self.session.client('securityhub')

    async def send_slack_alert(self, alert: Dict[str, Any]) -> None:
        """Send alert to Slack"""
        if not self.config.get('slack_webhook_url'):
            return

        try:
            payload = self._format_slack_message(alert)
            async with aiohttp.ClientSession() as session:
                async with session.post(self.config['slack_webhook_url'], json=payload) as resp:
                    if resp.status not in (200, 201):
                        raise Exception(f"Slack API returned status {resp.status}")
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {str(e)}")
            raise

    async def send_email_alert(self, alert: Dict[str, Any]) -> None:
        """Send alert via email"""
        if not self.config.get('email_config'):
            return

        try:
            message = self._create_email_message(alert)
            self.ses.send_raw_email(
                Source=self.config['email_config']['sender'],
                Destinations=self.config['email_config']['recipients'],
                RawMessage={'Data': message.as_string()}
            )
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {str(e)}")
            raise

    async def send_sns_alert(self, alert: Dict[str, Any]) -> None:
        """Send alert via SNS"""
        if not self.config.get('sns_topic_arn'):
            return

        try:
            self.sns.publish(
                TopicArn=self.config['sns_topic_arn'],
                Message=self._format_sns_message(alert),
                Subject=f"Security Alert - {alert['severity']}"
            )
        except Exception as e:
            self.logger.error(f"Failed to send SNS alert: {str(e)}")
            raise

    async def create_security_hub_finding(self, alert: Dict[str, Any]) -> None:
        """Create finding in Security Hub"""
        if not self.config.get('security_hub_enabled'):
            return

        try:
            finding = self._format_security_hub_finding(alert)
            self.securityhub.batch_import_findings(
                Findings=[finding]
            )
        except Exception as e:
            self.logger.error(f"Failed to create Security Hub finding: {str(e)}")
            raise

    def _format_slack_message(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Format alert for Slack"""
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🚨 Security Alert - {alert['severity']}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Rule:* {alert['rule_name']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Affected Resources:* {alert['context']['resource_count']}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Findings:*\n" + "\n".join(
                            f"• {finding['description']}"
                            for finding in alert['findings'][:5]
                        )
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Recommendations:*\n" + "\n".join(
                            f"• {rec}" for rec in alert['context']['recommendations'][:3]
                        )
                    }
                }
            ]
        }

    def _create_email_message(self, alert: Dict[str, Any]) -> MIMEMultipart:
        """Create email message"""
        message = MIMEMultipart()
        message['Subject'] = f"Security Alert - {alert['severity']} - {alert['rule_name']}"
        message['From'] = self.config['email_config']['sender']
        message['To'] = ', '.join(self.config['email_config']['recipients'])

        html = self._generate_email_html(alert)
        message.attach(MIMEText(html, 'html'))

        return message

    def _format_sns_message(self, alert: Dict[str, Any]) -> str:
        """Format alert for SNS"""
        return (
            f"Security Alert - {alert['severity']}\n"
            f"Rule: {alert['rule_name']}\n"
            f"Affected Services: {', '.join(alert['context']['affected_services'])}\n"
            f"Resource Count: {alert['context']['resource_count']}\n\n"
            "Findings:\n" +
            "\n".join(f"- {f['description']}" for f in alert['findings'][:5]) +
            "\n\nRecommendations:\n" +
            "\n".join(f"- {r}" for r in alert['context']['recommendations'][:3])
        )

    def _format_security_hub_finding(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Format alert for Security Hub"""
        # Implementation depends on Security Hub finding format requirements
        pass

    def _generate_email_html(self, alert: Dict[str, Any]) -> str:
        """Generate HTML email content"""
        # Implementation for HTML email template
        pass
