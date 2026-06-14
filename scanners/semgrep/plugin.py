
from typing import List

from core.plugins.base import ScannerPlugin
from core.models.finding import Finding

class SemgrepPlugin(ScannerPlugin):
    name = 'semgrep'
    version = '0.1.0'

    def scan(self, target: str) -> List[Finding]:
        return [
            Finding(
                id=f'semgrep-{target}-1',
                source='semgrep',
                severity='low',
                title='Example Semgrep finding',
                description='A placeholder Semgrep finding for the target.',
                evidence=[f'{target}/src'],
            )
        ]
