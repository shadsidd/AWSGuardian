# aws_security_scanner/core/base_scanner.py
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import logging
import boto3
from datetime import datetime
from ..core.exceptions import ScannerError

class BaseScanner(ABC):
    """Base class for all AWS service scanners"""

    def __init__(self, session: boto3.Session, config: Dict[str, Any]):
        self.session = session
        self.config = config
        self.findings: List[Dict[str, Any]] = []
        self.logger = logging.getLogger(self.__class__.__name__)
        self.start_time = None
        self.end_time = None

    @abstractmethod
    async def scan(self) -> None:
        """Implement the scanning logic for specific service"""
        pass

    def add_finding(
        self,
        service: str,
        resource: str,
        risk_factors: Dict[str, int],
        description: str,
        recommendation: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add a security finding"""
        risk_level = self._calculate_risk_level(risk_factors)

        finding = {
            "id": self._generate_finding_id(service, resource),
            "timestamp": datetime.utcnow().isoformat(),
            "service": service,
            "resource": resource,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "risk_score": sum(risk_factors.values()),
            "description": description,
            "recommendation": recommendation,
            "details": details or {},
            "region": self.session.region_name,
            "account_id": self._get_account_id()
        }

        self.findings.append(finding)
        self.logger.info(f"Added finding: {finding['id']} - {risk_level} risk")

    def _calculate_risk_level(self, risk_factors: Dict[str, int]) -> str:
        """Calculate risk level based on risk factors"""
        total_risk = sum(risk_factors.values())

        if total_risk >= self.config["risk_threshold"]["Critical"]:
            return "Critical"
        elif total_risk >= self.config["risk_threshold"]["High"]:
            return "High"
        elif total_risk >= self.config["risk_threshold"]["Medium"]:
            return "Medium"
        else:
            return "Low"

    def _generate_finding_id(self, service: str, resource: str) -> str:
        """Generate unique finding ID"""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return f"{service}-{resource}-{timestamp}"

    def _get_account_id(self) -> str:
        """Get AWS account ID"""
        try:
            return self.session.client('sts').get_caller_identity()['Account']
        except Exception as e:
            self.logger.error(f"Failed to get account ID: {str(e)}")
            return "unknown"

    async def run(self) -> List[Dict[str, Any]]:
        """Run the scanner"""
        self.start_time = datetime.utcnow()
        self.logger.info(f"Starting {self.__class__.__name__} scan")

        try:
            await self.scan()
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            raise ScannerError(f"Scan failed: {str(e)}")
        finally:
            self.end_time = datetime.utcnow()
            duration = (self.end_time - self.start_time).total_seconds()
            self.logger.info(f"Scan completed in {duration:.2f} seconds")

        return self.findings

    def get_scan_metadata(self) -> Dict[str, Any]:
        """Get scan metadata"""
        return {
            "scanner": self.__class__.__name__,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else None,
            "finding_count": len(self.findings)
        }
