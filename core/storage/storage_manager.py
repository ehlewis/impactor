from typing import List, Optional

from core.models.finding import Finding
from core.storage.base import StorageProvider
from core.storage.sqlite_provider import SQLiteProvider

class StorageManager:
    def __init__(self, provider: Optional[StorageProvider] = None):
        self.provider = provider or SQLiteProvider()

    def save_findings(self, findings: List[Finding]) -> None:
        self.provider.save_findings(findings)

    def load_findings(self, application_id: str = None) -> List[Finding]:
        return self.provider.load_findings(application_id)

    def list_findings(self) -> List[Finding]:
        return self.provider.list_findings()

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        return self.provider.get_finding(finding_id)
