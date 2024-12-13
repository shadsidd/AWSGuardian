from .base_formatter import BaseFormatter
from typing import Dict, Any
import json

class JSONFormatter(BaseFormatter):
    """JSON report formatter"""

    def format(self) -> Dict[str, Any]:
        """Format report as JSON"""
        return {
            "metadata": self.metadata,
            "findings": [finding.to_dict() for finding in self.findings]
        }
