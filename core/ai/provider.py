from abc import ABC, abstractmethod
import json
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

    def _build_enrichment_prompt(
        self,
        findings: list[Dict],
        recommendations: List[Dict],
        code_context: Optional[Dict[str, str]] = None,
    ) -> str:
        finding_details = [
            {
                key: finding.get(key)
                for key in (
                    'id', 'title', 'severity', 'description', 'path', 'evidence',
                    'application_id', 'application_name', 'repository_root',
                )
                if finding.get(key) is not None
            }
            for finding in findings
        ]
        context = {
            path: snippet[:3000]
            for path, snippet in (code_context or {}).items()
        }
        return (
            'Assess these deterministic application-security remediation recommendations. '
            'Use the finding data and supplied code context as evidence. Keep the deterministic '
            'recommendation and its impacted finding IDs intact; add prioritization context rather '
            'than inventing findings or claiming unprovided code behavior. '
            'For each recommendation, assess severity, impact to the application or its users, '
            'prevalence (how many findings and distinct code locations are affected), and fix '
            'complexity (the likely engineering effort). Distinguish observed facts from estimates, '
            'and state when evidence is insufficient. Rank recommendations highest priority first. '
            'Return only valid JSON with this shape: '
            '{"assessments":[{"recommendation_id":"...","rank":1,'
            '"priority":"Critical|High|Medium|Low",'
            '"factors":{"severity":{"rating":"...","rationale":"..."},'
            '"impact":{"rating":"low|medium|high","rationale":"..."},'
            '"prevalence":{"rating":"low|medium|high","affected_findings":0,'
            '"distinct_locations":0,"rationale":"..."},'
            '"fix_complexity":{"rating":"low|medium|high","rationale":"..."}},'
            '"priority_rationale":"...","confidence":0.0,"evidence_gaps":[]}]}\n\n'
            f'Findings:\n{json.dumps(finding_details, indent=2, default=str)}\n\n'
            f'Deterministic recommendations:\n{json.dumps(recommendations, indent=2, default=str)}\n\n'
            f'Code context:\n{json.dumps(context, indent=2, default=str)}'
        )
