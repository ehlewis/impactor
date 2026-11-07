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
                title='First issue',
                description='Problem in code',
                path='src/app/routes.py',
                evidence=['src/app/routes.py:10'],
            ),
            Finding(
                id='2',
                source='snyk',
                severity='high',
                title='Second issue',
                description='Problem in code',
                path='src/app/routes.py',
                evidence=['src/app/routes.py:15'],
            ),
        ]

        recommendations = recommend_fixes(findings)
        self.assertEqual(len(recommendations), 1)
        self.assertIn('src/app/routes.py:10', recommendations[0].shared_code)
        self.assertIn('src/app/routes.py:15', recommendations[0].shared_code)
        self.assertEqual(recommendations[0].impacted_findings, ['1', '2'])

    def test_same_relative_path_in_different_repositories_is_not_grouped(self):
        findings = [
            Finding(
                id='repo-a',
                source='snyk',
                severity='high',
                title='Issue',
                path='src/routes.py',
                repository_root='/work/repo-a',
                application_id='app-a',
            ),
            Finding(
                id='repo-b',
                source='snyk',
                severity='high',
                title='Issue',
                path='src/routes.py',
                repository_root='/work/repo-b',
                application_id='app-b',
            ),
        ]

        recommendations = recommend_fixes(findings)

        self.assertEqual(len(recommendations), 2)
        self.assertCountEqual(
            [recommendation.impacted_findings for recommendation in recommendations],
            [['repo-a'], ['repo-b']],
        )


if __name__ == '__main__':
    unittest.main()
