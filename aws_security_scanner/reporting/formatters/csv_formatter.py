from .base_formatter import BaseFormatter
import csv
from io import StringIO

class CSVFormatter(BaseFormatter):
    """CSV report formatter"""

    def format(self) -> str:
        """Format report as CSV"""
        output = StringIO()
        writer = csv.writer(output)

        # Write headers
        writer.writerow([
            'Service',
            'Resource',
            'Risk Level',
            'Description',
            'Recommendation',
            'Risk Factors'
        ])

        # Write findings
        for finding in self.findings:
            writer.writerow([
                finding.service,
                finding.resource,
                self._calculate_risk_level(finding.risk_factors),
                finding.description,
                finding.recommendation,
                str(finding.risk_factors)
            ])

        return output.getvalue()

    def _calculate_risk_level(self, risk_factors: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        max_risk = max(risk_factors.values())
        if max_risk >= 9:
            return 'Critical'
        elif max_risk >= 7:
            return 'High'
        elif max_risk >= 4:
            return 'Medium'
        return 'Low'
