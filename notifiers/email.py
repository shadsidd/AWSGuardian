# notifiers/email.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import Dict, List, Any
from jinja2 import Template
from .base import BaseNotifier
from ..models.finding import Finding
from ..utils.exceptions import NotificationError

class EmailNotifier(BaseNotifier):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.smtp_config = config.get('smtp', {})
        self.sender = config['sender']
        self.recipients = config['recipients']
        self.template = self._load_template()

    def send(self, findings: List[Finding], context: Dict[str, Any] = None) -> bool:
        try:
            if not self.should_notify(findings):
                return False

            message = self._create_email_message(findings, context)

            with smtplib.SMTP(
                self.smtp_config['host'],
                self.smtp_config['port']
            ) as server:
                if self.smtp_config.get('use_tls', True):
                    server.starttls()

                if 'username' in self.smtp_config:
                    server.login(
                        self.smtp_config['username'],
                        self.smtp_config['password']
                    )

                server.send_message(message)

            return True

        except Exception as e:
            self.logger.error(f"Error sending email notification: {str(e)}")
            raise NotificationError(f"Failed to send email notification: {str(e)}")

    def _create_email_message(
        self,
        findings: List[Finding],
        context: Dict[str, Any] = None
    ) -> MIMEMultipart:
        message = MIMEMultipart('mixed')
        message['Subject'] = self._get_email_subject(findings)
        message['From'] = self.sender
        message['To'] = ', '.join(self.recipients)

        # HTML body
        html_content = self.format_message(findings, context)
        html_part = MIMEText(html_content, 'html')
        message.attach(html_part)

        # Attach report if available
        if context and 'report_path' in context:
            with open(context['report_path'], 'rb') as f:
                report = MIMEApplication(f.read(), _subtype='pdf')
                report.add_header(
                    'Content-Disposition',
                    'attachment',
                    filename='security_report.pdf'
                )
                message.attach(report)

        return message

    def _get_email_subject(self, findings: List[Finding]) -> str:
        critical_count = sum(1 for f in findings if f.risk_level == 'CRITICAL')
        if critical_count > 0:
            return f"🚨 CRITICAL - {critical_count} Critical Security Findings Detected"
        return "Security Scan Results"

    def format_message(self, findings: List[Finding], context: Dict[str, Any] = None) -> str:
        template_data = {
            'findings': findings,
            'summary': self._create_summary(findings),
            'context': context or {},
            'critical_findings': [f for f in findings if f.risk_level == 'CRITICAL'],
            'high_findings': [f for f in findings if f.risk_level == 'HIGH'],
            'resource_groups': self._group_findings_by_resource(findings)
        }

        return self.template.render(**template_data)

    def _create_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        return {
            'total_findings': len(findings),
            'critical_count': sum(1 for f in findings if f.risk_level == 'CRITICAL'),
            'high_count': sum(1 for f in findings if f.risk_level == 'HIGH'),
            'medium_count': sum(1 for f in findings if f.risk_level == 'MEDIUM'),
            'low_count': sum(1 for f in findings if f.risk_level == 'LOW'),
            'affected_resources': len(set(f.resource_id for f in findings))
        }

    def _group_findings_by_resource(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        groups = {}
        for finding in findings:
            if finding.resource_id not in groups:
                groups[finding.resource_id] = []
            groups[finding.resource_id].append(finding)
        return groups

    def _load_template(self) -> Template:
        template_path = self.config.get('template_path', 'templates/email.html')
        try:
            with open(template_path, 'r') as f:
                return Template(f.read())
        except Exception as e:
            self.logger.error(f"Error loading email template: {str(e)}")
            return Template(self._get_default_template())

    def _get_default_template(self) -> str:
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                /* Add your CSS styles here */
            </style>
        </head>
        <body>
            <h1>Security Scan Results</h1>

            <div class="summary">
                <h2>Summary</h2>
                <p>Total Findings: {{ summary.total_findings }}</p>
                <p>Critical: {{ summary.critical_count }}</p>
                <p>High: {{ summary.high_count }}</p>
                <p>Medium: {{ summary.medium_count }}</p>
                <p>Low: {{ summary.low_count }}</p>
            </div>

            {% if critical_findings %}
            <div class="critical-findings">
                <h2>Critical Findings</h2>
                {% for finding in critical_findings %}
                <div class="finding">
                    <h3>{{ finding.description }}</h3>
                    <p>Resource: {{ finding.resource_id }}</p>
                    <p>Details: {{ finding.details }}</p>
                </div>
                {% endfor %}
            </div>
            {% endif %}

            {% for resource_id, findings in resource_groups.items() %}
            <div class="resource-group">
                <h2>Resource: {{ resource_id }}</h2>
                {% for finding in findings %}
                <div class="finding">
                    <p>{{ finding.description }}</p>
                    <p>Risk Level: {{ finding.risk_level }}</p>
                </div>
                {% endfor %}
            </div>
            {% endfor %}
        </body>
        </html>
        """
