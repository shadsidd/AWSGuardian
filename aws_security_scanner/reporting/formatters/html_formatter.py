# aws_security_scanner/reporting/formatters/html_formatter.py
from .base_formatter import BaseFormatter
import jinja2
import os

class HTMLFormatter(BaseFormatter):
    """HTML report formatter"""

    def format(self) -> str:
        """Format report as HTML"""
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=True
        )

        template = env.get_template('report.html')
        return template.render(
            metadata=self.metadata,
            findings=self.findings
        )
