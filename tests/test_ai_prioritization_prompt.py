import unittest

from core.ai.ollama_provider import OllamaProvider
from core.ai.openai_provider import OpenAIProvider


class TestAIPrioritizationPrompt(unittest.TestCase):
    def test_openai_and_ollama_share_structured_contextual_assessment(self):
        findings = [{
            'id': 'finding-1',
            'title': 'SQL injection',
            'severity': 'high',
            'application_id': 'payments',
            'application_name': 'Payments',
            'repository_root': '/work/payments',
            'evidence': ['src/api.py:42'],
        }]
        recommendations = [{
            'id': 'fix-1',
            'impacted_findings': ['finding-1'],
            'effort': 'medium',
            'shared_code': ['src/api.py:42'],
        }]
        context = {'/work/payments/src/api.py': 'def query(user_input): ...'}

        openai_prompt = OpenAIProvider()._build_enrichment_prompt(findings, recommendations, context)
        ollama_prompt = OllamaProvider()._build_enrichment_prompt(findings, recommendations, context)

        self.assertEqual(openai_prompt, ollama_prompt)
        for expected in (
            'severity', 'impact', 'prevalence', 'fix_complexity', 'priority_rationale',
            'application_name', 'repository_root', 'distinct_locations', 'valid JSON',
        ):
            self.assertIn(expected, openai_prompt)
        self.assertIn('/work/payments', openai_prompt)
        self.assertIn('finding-1', openai_prompt)


if __name__ == '__main__':
    unittest.main()