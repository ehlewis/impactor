from typing import Dict, List, Optional

from core.ai.provider import AIProvider

class LocalStubProvider(AIProvider):
    name = 'local-stub'
    version = '0.1.0'

    def summarize_findings(
        self,
        findings: List[Dict],
        code_context: Optional[Dict[str, str]] = None,
    ) -> str:
        if not findings:
            return 'No findings were discovered.'
        return (
            f'Found {len(findings)} findings. '
            'The highest impact issues are grouped by severity and evidence overlap.'
        )

    def recommend_fix_priorities(
        self,
        findings: List[Dict],
        code_context: Optional[Dict[str, str]] = None,
    ) -> Dict:
        issues = []
        for finding in findings:
            issues.append({
                'id': finding.get('id'),
                'title': finding.get('title'),
                'severity': finding.get('severity'),
                'recommendation': 'Investigate and fix the root cause in code and dependencies.',
                'effort': 'medium' if finding.get('severity', '').lower() in ['high', 'critical'] else 'low',
            })
        return {
            'provider': self.name,
            'recommendations': issues,
            'reasoning': 'Stub-based reasoning: prioritize by severity and grouping across related findings.',
        }

    def enrich_fix_recommendations(
        self,
        findings: List[Dict],
        recommendations: List[Dict],
        code_context: Optional[Dict[str, str]] = None,
    ) -> Dict:
        return {
            'provider': self.name,
            'recommendations': recommendations,
            'reasoning': 'Local stub enrichment: returning deterministic recommendations unchanged.',
        }
