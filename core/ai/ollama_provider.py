import os
from typing import Dict, List, Optional

import requests

from core.ai.provider import AIProvider
from core.config.env_loader import get_env_variable

class OllamaProvider(AIProvider):
    name = 'ollama'
    version = '0.1.0'

    def __init__(self):
        self.api_base = os.getenv('OLLAMA_API_BASE', 'http://localhost:11434')
        self.model = os.getenv('OLLAMA_MODEL', '')
        self.api_key = get_env_variable('OLLAMA_API_KEY')

    def is_configured(self) -> bool:
        return bool(self.model)

    def _call_api(self, prompt: str, system: str = '') -> Optional[str]:
        if not self.model:
            return None

        url = f'{self.api_base}/v1/chat/completions'
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'

        payload = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': system},
                {'role': 'user', 'content': prompt},
            ],
            'temperature': 0.2,
        }
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        message = data.get('choices', [])[0].get('message', {})
        return message.get('content')

    def summarize_findings(self, findings: List[Dict], code_context: Optional[Dict[str, str]] = None) -> str:
        prompt = self._build_summary_prompt(findings, code_context)
        return self._call_api(prompt, system='You are an application security analyst.') or ''

    def recommend_fix_priorities(
        self,
        findings: List[Dict],
        code_context: Optional[Dict[str, str]] = None,
    ) -> Dict:
        prompt = self._build_prioritization_prompt(findings, code_context)
        content = self._call_api(prompt, system='You are an application security risk advisor.')
        return {
            'provider': self.name,
            'recommendations': content or '',
        }

    def enrich_fix_recommendations(
        self,
        findings: List[Dict],
        recommendations: List[Dict],
        code_context: Optional[Dict[str, str]] = None,
    ) -> Dict:
        prompt = self._build_enrichment_prompt(findings, recommendations, code_context)
        content = self._call_api(prompt, system='You are an application security risk advisor.')
        return {
            'provider': self.name,
            'recommendations': content or '',
        }

    def _build_summary_prompt(self, findings: List[Dict], code_context: Optional[Dict[str, str]] = None) -> str:
        findings_json = '\n'.join([
            f"- {finding.get('id')}: {finding.get('title')} ({finding.get('severity')})"
            for finding in findings
        ])
        context_section = ''
        if code_context:
            context_section = '\n\nCode context samples:\n' + '\n'.join(
                [f"{path}: {snippet[:200].replace('\n', ' ')}..." for path, snippet in code_context.items()]
            )
        return (
            'Analyze the following findings and provide a brief summary of the most critical risk areas. '
            'Include the top 3 impact categories and why they matter.\n\n'
            f'Findings:\n{findings_json}'
            f'{context_section}'
        )

    def _build_prioritization_prompt(self, findings: List[Dict], code_context: Optional[Dict[str, str]] = None) -> str:
        findings_json = '\n'.join([
            f"- {finding.get('id')}: {finding.get('title')} ({finding.get('severity')}). Evidence: {finding.get('evidence')}"
            for finding in findings
        ])
        context_section = ''
        if code_context:
            context_section = '\n\nRelevant code context samples:\n' + '\n'.join(
                [f"{path}: {snippet[:200].replace('\n', ' ')}..." for path, snippet in code_context.items()]
            )
        return (
            'Analyze the following application security findings and recommend the highest impact fixes. '
            'For each recommendation, include which findings it remediates, the estimated effort, and why it is high impact. '
            'Use code context, function summaries, and flow information when available to understand whether the finding is in production business logic or test/sample/demo scaffolding. '
            'If a finding appears in a test, fixture, or spec file containing hardcoded credentials, treat it as low priority and explain that it is likely intentional test data rather than a production secret leak.\n\n'
            f'Findings:\n{findings_json}'
            f'{context_section}'
        )

    def _build_enrichment_prompt(
        self,
        findings: List[Dict],
        recommendations: List[Dict],
        code_context: Optional[Dict[str, str]] = None,
    ) -> str:
        findings_json = '\n'.join([
            f"- {finding.get('id')}: {finding.get('title')} ({finding.get('severity')}) - {finding.get('description')}"
            for finding in findings
        ])
        recommendations_json = '\n'.join([
            f"- {rec.get('id')}: {rec.get('title')} | effort={rec.get('effort')} | priority={rec.get('priority')} | remediation={rec.get('remediation')}"
            for rec in recommendations
        ])
        context_section = ''
        if code_context:
            context_section = '\n\nRelevant code context samples:\n' + '\n'.join(
                [f"{path}: {snippet[:200].replace('\n', ' ')}..." for path, snippet in code_context.items()]
            )
        return (
            'You are an application security risk advisor. Here are deterministic fix recommendations already computed by Impactor. '
            'Use the code context to enrich those recommendations with extra reasoning, and indicate whether any priorities or effort estimates should be adjusted based on likely code behavior. '
            'Do not replace the deterministic recommendations unless there is strong evidence from the code context. '
            'Provide a concise summary of suggested adjustments and the reasoning for each recommendation.\n\n'
            f'Findings:\n{findings_json}\n\n'
            f'Recommendations:\n{recommendations_json}'
            f'{context_section}'
        )
