from abc import ABC, abstractmethod
from typing import Dict, List, Optional

class AIProvider(ABC):
    name: str = ''
    version: str = '0.1.0'

    @abstractmethod
    def summarize_findings(self, findings: list[Dict], code_context: Optional[Dict[str, str]] = None) -> str:
        raise NotImplementedError

    @abstractmethod
    def enrich_fix_recommendations(
        self,
        findings: list[Dict],
        recommendations: List[Dict],
        code_context: Optional[Dict[str, str]] = None,
    ) -> Dict:
        raise NotImplementedError

    def is_configured(self) -> bool:
        return True
