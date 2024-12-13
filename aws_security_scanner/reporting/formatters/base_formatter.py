from abc import ABC, abstractmethod
from typing import List, Dict, Any
from ...core.findings import Finding

class BaseFormatter(ABC):
    """Base class for report formatters"""

    def __init__(self, findings: List[Finding], metadata: Dict[str, Any]):
        self.findings = findings
        self.metadata = metadata

    @abstractmethod
    def format(self) -> Any:
        """Format the report"""
        pass
