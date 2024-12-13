from .base_formatter import BaseFormatter
from typing import Dict, Any
from colorama import init, Fore, Style

class ConsoleFormatter(BaseFormatter):
    """Console report formatter with colored output"""

    def __init__(self, findings: List[Finding], metadata: Dict[str, Any]):
        super().__init__(findings, metadata)
        init()  # Initialize colorama

    def format(self) -> str:
        """Format report for console output"""
        output = []

        # Add header
        output.append(self._format_header())

        # Add summary
        output.append(self._format_summary())

        # Add findings
        output.append(self._format_findings())

        return '\n'.join(output)

    def _format_header(self) -> str:
        """Format report header"""
        return f"""
{Fore.CYAN}AWS Security Scanner Report{Style.RESET_ALL}
{Fore.CYAN}={'=' * 50}{Style.RESET_ALL}
Account ID: {self.metadata['account_id']}
Scan Date: {self.metadata['scan_date']}
"""

    def _format_summary(self) -> str:
        """Format findings summary"""
        risk_summary = self.metadata['risk_summary']
        return f"""
{Fore.YELLOW}Summary{Style.RESET_ALL}
{Fore.YELLOW}{'-' * 50}{Style.RESET_ALL}
{Fore.RED}Critical: {risk_summary['critical']}{Style.RESET_ALL}
{Fore.MAGENTA}High: {risk_summary['high']}{Style.RESET_ALL}
{Fore.YELLOW}Medium: {risk_summary['medium']}{Style.RESET_ALL}
{Fore.GREEN}Low: {risk_summary['low']}{Style.RESET_ALL}
"""

    def _format_findings(self) -> str:
        """Format detailed findings"""
        output = [f"\n{Fore.YELLOW}Detailed Findings{Style.RESET_ALL}"]
        output.append(f"{Fore.YELLOW}{'-' * 50}{Style.RESET_ALL}")

        for finding in self.findings:
            risk_level = self._get_risk_level_color(finding.risk_factors)
            output.append(f"""
{risk_level}[{self._calculate_risk_level(finding.risk_factors)}] {finding.service}/{finding.resource}{Style.RESET_ALL}
Description: {finding.description}
Recommendation: {finding.recommendation}
Risk Factors: {finding.risk_factors}
""")

        return '\n'.join(output)

    def _get_risk_level_color(self, risk_factors: Dict[str, int]) -> str:
        """Get color based on risk level"""
        max_risk = max(risk_factors.values())
        if max_risk >= 9:
            return Fore.RED
        elif max_risk >= 7:
            return Fore.MAGENTA
        elif max_risk >= 4:
            return Fore.YELLOW
        return Fore.GREEN

    def _calculate_risk_level(self, risk_factors: Dict[str, int]) -> str:
        """Calculate risk level string"""
        max_risk = max(risk_factors.values())
        if max_risk >= 9:
            return 'CRITICAL'
        elif max_risk >= 7:
            return 'HIGH'
        elif max_risk >= 4:
            return 'MEDIUM'
        return 'LOW'
