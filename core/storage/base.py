from abc import ABC, abstractmethod
from typing import List

from core.models.finding import Finding

class StorageProvider(ABC):
    @abstractmethod
    def save_finding(self, finding: Finding) -> None:
        raise NotImplementedError

    @abstractmethod
    def save_findings(self, findings: List[Finding]) -> None:
        raise NotImplementedError

    @abstractmethod
    def load_findings(self, application_id: str = None) -> List[Finding]:
        raise NotImplementedError

    @abstractmethod
    def list_findings(self) -> List[Finding]:
        raise NotImplementedError
