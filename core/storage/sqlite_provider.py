
import sqlite3
from pathlib import Path
from typing import List, Optional

from core.models.finding import Finding
from core.storage.base import StorageProvider

class SQLiteProvider(StorageProvider):
    def __init__(self, path: str = 'impactor.db'):
        self.path = path
        self._ensure_schema()

    def _ensure_schema(self):
        db_path = Path(self.path)
        if db_path.parent:
            db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                'CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, source TEXT, severity TEXT, title TEXT, description TEXT, path TEXT, application_id TEXT)'
            )
            conn.execute(
                'CREATE TABLE IF NOT EXISTS findings_evidence (finding_id TEXT, evidence TEXT)'
            )
            cursor = conn.execute("PRAGMA table_info(findings)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'path' not in columns:
                conn.execute('ALTER TABLE findings ADD COLUMN path TEXT')

    def save_finding(self, finding: Finding) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                'INSERT OR REPLACE INTO findings (id, source, severity, title, description, path, application_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (finding.id, finding.source, finding.severity, finding.title, finding.description, finding.path, finding.application_id),
            )
            conn.execute('DELETE FROM findings_evidence WHERE finding_id = ?', (finding.id,))
            for evidence_item in finding.evidence:
                conn.execute(
                    'INSERT INTO findings_evidence (finding_id, evidence) VALUES (?, ?)',
                    (finding.id, evidence_item),
                )

    def save_findings(self, findings: List[Finding]) -> None:
        for finding in findings:
            self.save_finding(finding)

    def load_findings(self, application_id: str = None) -> List[Finding]:
        query = 'SELECT id, source, severity, title, description, path, application_id FROM findings'
        params: List[str] = []
        if application_id:
            query += ' WHERE application_id = ?'
            params.append(application_id)

        results: List[Finding] = []
        with sqlite3.connect(self.path) as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            for row in rows:
                finding_id, source, severity, title, description, path, app_id = row
                evidence = [
                    ev_row[0]
                    for ev_row in conn.execute('SELECT evidence FROM findings_evidence WHERE finding_id = ?', (finding_id,))
                ]
                results.append(
                    Finding(
                        id=finding_id,
                        source=source,
                        severity=severity,
                        title=title,
                        description=description,
                        path=path or '',
                        application_id=app_id,
                        evidence=evidence,
                    )
                )
        return results

    def list_findings(self) -> List[Finding]:
        return self.load_findings()

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        findings = self.load_findings()
        for finding in findings:
            if finding.id == finding_id:
                return finding
        return None
