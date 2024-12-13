# aws_security_scanner/reporting/executive_summary.py
from typing import Dict, Any, List
from ..core.findings import Finding
import pandas as pd
from datetime import datetime, timedelta

class ExecutiveSummaryGenerator:
    """Generates executive summary reports with trends and actionable insights"""

    def __init__(self, findings: List[Finding], metadata: Dict[str, Any], historical_data: Dict[str, Any] = None):
        self.findings = findings
        self.metadata = metadata
        self.historical_data = historical_data or {}
        self._analysis = self._analyze_findings()

    def generate_summary(self) -> Dict[str, Any]:
        """Generate executive summary with key metrics and insights"""
        return {
            "overview": self._generate_overview(),
            "key_metrics": self._generate_key_metrics(),
            "critical_issues": self._get_critical_issues(),
            "compliance_status": self._generate_compliance_summary(),
            "trend_analysis": self._generate_trend_analysis(),
            "recommendations": self._generate_recommendations(),
            "risk_exposure": self._calculate_risk_exposure()
        }

    def _analyze_findings(self) -> Dict[str, Any]:
        """Analyze findings for patterns and insights"""
        return {
            "risk_distribution": self._analyze_risk_distribution(),
            "service_impact": self._analyze_service_impact(),
            "recurring_issues": self._identify_recurring_issues(),
            "compliance_gaps": self._identify_compliance_gaps()
        }

    def _generate_overview(self) -> Dict[str, Any]:
        """Generate high-level overview"""
        return {
            "scan_date": self.metadata["scan_date"],
            "account_id": self.metadata["account_id"],
            "total_findings": len(self.findings),
            "critical_findings": len([f for f in self.findings
                                   if max(f.risk_factors.values()) >= 9]),
            "overall_security_score": self._calculate_security_score(),
            "change_from_last_scan": self._calculate_change_from_last_scan()
        }

    def _generate_key_metrics(self) -> Dict[str, Any]:
        """Generate key security metrics"""
        return {
            "risk_levels": self.metadata["risk_summary"],
            "most_affected_services": self._get_most_affected_services(top_n=5),
            "average_risk_score": self._calculate_average_risk_score(),
            "remediation_priority_score": self._calculate_remediation_priority(),
            "security_posture_indicators": {
                "encryption_status": self._assess_encryption_status(),
                "access_control_status": self._assess_access_control(),
                "compliance_adherence": self._assess_compliance_adherence()
            }
        }

    def _get_critical_issues(self) -> List[Dict[str, Any]]:
        """Get detailed list of critical security issues"""
        critical_issues = []
        for finding in self.findings:
            max_risk = max(finding.risk_factors.values())
            if max_risk >= 9:
                critical_issues.append({
                    "service": finding.service,
                    "resource": finding.resource,
                    "risk_score": max_risk,
                    "description": finding.description,
                    "recommendation": finding.recommendation,
                    "estimated_effort": self._estimate_remediation_effort(finding),
                    "potential_impact": self._assess_potential_impact(finding)
                })
        return sorted(critical_issues, key=lambda x: x["risk_score"], reverse=True)

    def _generate_compliance_summary(self) -> Dict[str, Any]:
        """Generate compliance status summary"""
        return {
            "overall_status": self.metadata["compliance_status"]["overall_status"],
            "framework_compliance": self._assess_framework_compliance(),
            "control_gaps": self._identify_control_gaps(),
            "remediation_timeline": self._generate_remediation_timeline()
        }

    def _generate_trend_analysis(self) -> Dict[str, Any]:
        """Generate security trend analysis"""
        if not self.historical_data:
            return {"status": "insufficient_data"}

        return {
            "risk_trend": self._analyze_risk_trend(),
            "service_risk_evolution": self._analyze_service_risk_evolution(),
            "recurring_patterns": self._analyze_recurring_patterns(),
            "improvement_metrics": self._calculate_improvement_metrics()
        }

    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations"""
        recommendations = []

        # Group findings by service
        service_findings = {}
        for finding in self.findings:
            if finding.service not in service_findings:
                service_findings[finding.service] = []
            service_findings[finding.service].append(finding)

        # Generate recommendations for each service
        for service, findings in service_findings.items():
            recommendations.extend(self._generate_service_recommendations(service, findings))

        return sorted(recommendations, key=lambda x: x["priority"], reverse=True)

    def _calculate_risk_exposure(self) -> Dict[str, Any]:
        """Calculate overall risk exposure"""
        return {
            "overall_exposure_level": self._calculate_exposure_level(),
            "risk_factors": self._analyze_risk_factors(),
            "exposure_trends": self._analyze_exposure_trends(),
            "mitigation_status": self._analyze_mitigation_status()
        }

    def _calculate_security_score(self) -> float:
        """Calculate overall security score"""
        weights = {
            "critical": 1.0,
            "high": 0.7,
            "medium": 0.4,
            "low": 0.1
        }

        max_score = 100
        deductions = 0

        for finding in self.findings:
            max_risk = max(finding.risk_factors.values())
            if max_risk >= 9:
                deductions += weights["critical"] * 10
            elif max_risk >= 7:
                deductions += weights["high"] * 7
            elif max_risk >= 4:
                deductions += weights["medium"] * 4
            else:
                deductions += weights["low"] * 1

        return max(0, max_score - deductions)

    def _estimate_remediation_effort(self, finding: Finding) -> str:
        """Estimate effort required for remediation"""
        # Implementation based on finding type and complexity
        effort_patterns = {
            "encryption": "low",
            "access_control": "medium",
            "configuration": "low",
            "architecture": "high",
            "compliance": "medium"
        }

        for pattern, effort in effort_patterns.items():
            if pattern in finding.description.lower():
                return effort
        return "medium"

    def _assess_potential_impact(self, finding: Finding) -> Dict[str, Any]:
        """Assess potential impact of the finding"""
        return {
            "business_impact": self._assess_business_impact(finding),
            "data_impact": self._assess_data_impact(finding),
            "operational_impact": self._assess_operational_impact(finding),
            "reputation_impact": self._assess_reputation_impact(finding)
        }

    def to_pdf(self, output_path: str) -> None:
        """Generate PDF executive summary report"""
        # Implementation for PDF generation
        pass

    def to_presentation(self, output_path: str) -> None:
        """Generate PowerPoint executive summary presentation"""
        # Implementation for presentation generation
        pass
