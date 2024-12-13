# aws_security_scanner/reporting/report_generator.py
from typing import List, Dict, Any, Type
from ..core.findings import Finding
from .formatters.base_formatter import BaseFormatter
from datetime import datetime
import logging

class ReportGenerator:
    """Main class for generating security assessment reports"""

    def __init__(self, findings: List[Finding], account_id: str):
        self.findings = findings
        self.account_id = account_id
        self.logger = logging.getLogger(__name__)
        self._report_metadata = self._generate_metadata()

    def generate(self, formatter: Type[BaseFormatter], output_path: str = None) -> Any:
        """Generate report using specified formatter"""
        try:
            formatted_report = formatter(
                findings=self.findings,
                metadata=self._report_metadata
            ).format()

            if output_path:
                self._save_report(formatted_report, output_path)

            return formatted_report
        except Exception as e:
            self.logger.error(f"Failed to generate report: {str(e)}")
            raise

    def _generate_metadata(self) -> Dict[str, Any]:
        """Generate report metadata"""
        total_findings = len(self.findings)
        risk_levels = self._calculate_risk_levels()

        return {
            "account_id": self.account_id,
            "scan_date": datetime.utcnow().isoformat(),
            "total_findings": total_findings,
            "risk_summary": {
                "critical": risk_levels["critical"],
                "high": risk_levels["high"],
                "medium": risk_levels["medium"],
                "low": risk_levels["low"]
            },
            "services_affected": self._get_affected_services(),
            "compliance_status": self._calculate_compliance_status()
        }

    def _calculate_risk_levels(self) -> Dict[str, int]:
        """Calculate number of findings per risk level"""
        risk_levels = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        for finding in self.findings:
            max_risk = max(finding.risk_factors.values())
            if max_risk >= 9:
                risk_levels["critical"] += 1
            elif max_risk >= 7:
                risk_levels["high"] += 1
            elif max_risk >= 4:
                risk_levels["medium"] += 1
            else:
                risk_levels["low"] += 1

        return risk_levels

    def _get_affected_services(self) -> Dict[str, int]:
        """Get count of findings per AWS service"""
        services = {}
        for finding in self.findings:
            services[finding.service] = services.get(finding.service, 0) + 1
        return services

    def _calculate_compliance_status(self) -> Dict[str, Any]:
        """Calculate compliance status based on findings"""
        return {
            "overall_status": self._get_overall_compliance_status(),
            "failing_controls": self._get_failing_controls(),
            "passing_controls": self._get_passing_controls()
        }

    def _get_overall_compliance_status(self) -> str:
        """Determine overall compliance status"""
        risk_levels = self._calculate_risk_levels()
        if risk_levels["critical"] > 0:
            return "Failed"
        elif risk_levels["high"] > 0:
            return "At Risk"
        elif risk_levels["medium"] > 0:
            return "Needs Improvement"
        else:
            return "Compliant"

    def _get_failing_controls(self) -> List[Dict[str, Any]]:
        """Get list of failing security controls"""
        failing_controls = []
        for finding in self.findings:
            if max(finding.risk_factors.values()) >= 7:
                failing_controls.append({
                    "service": finding.service,
                    "resource": finding.resource,
                    "description": finding.description,
                    "risk_factors": finding.risk_factors
                })
        return failing_controls

    def _get_passing_controls(self) -> List[str]:
        """Get list of passing security controls"""
        # Implementation depends on specific security controls being checked
        # This is a placeholder for actual implementation
        return []

    def _save_report(self, report: Any, output_path: str) -> None:
        """Save report to file"""
        try:
            with open(output_path, 'w') as f:
                if isinstance(report, (dict, list)):
                    import json
                    json.dump(report, f, indent=2)
                else:
                    f.write(str(report))
        except Exception as e:
            self.logger.error(f"Failed to save report to {output_path}: {str(e)}")
            raise
