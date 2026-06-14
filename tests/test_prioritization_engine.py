import unittest

from core.models.finding import Finding
from core.risk.prioritization_engine import recommend_fixes


class TestPrioritizationEngine(unittest.TestCase):
    def test_shared_code_uses_finding_path(self):
        findings = [
            Finding(
                id='1',
                source='snyk',
                severity='high',
                title='Test issue',
                description='Problem in code',
                path='src/app/routes.py',
                evidence=['src/app/routes.py:10'],
            ),
            Finding(
                id='2',
                source='snyk',
                severity='high',
                title='Test issue',
                description='Problem in code',
                path='src/app/routes.py',
                evidence=['src/app/routes.py:15'],
            ),
        ]

        recommendations = recommend_fixes(findings)
        self.assertEqual(len(recommendations), 1)
        self.assertIn('src/app/routes.py:10', recommendations[0].shared_code)
        self.assertIn('src/app/routes.py:15', recommendations[0].shared_code)


if __name__ == '__main__':
    unittest.main()
