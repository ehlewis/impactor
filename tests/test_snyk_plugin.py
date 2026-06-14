import json
import unittest
from unittest.mock import patch

from scanners.snyk.plugin import _extract_snyk_issues, SnykAPIPlugin, SnykCLIPlugin


class TestSnykPluginParsing(unittest.TestCase):
    def test_extracts_top_level_issue_list(self):
        sample = {
            "issues": [
                {"id": "1", "title": "Test issue", "severity": "high"}
            ]
        }

        issues = _extract_snyk_issues(sample)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["id"], "1")
        self.assertEqual(issues[0]["severity"], "high")

    def test_extracts_nested_issue_lists(self):
        sample = {
            "someKey": {
                "deep": [
                    {"id": "2", "title": "Nested issue", "severity": "medium"}
                ]
            },
            "data": {
                "results": [
                    {"id": "3", "title": "Nested result", "severity": "low"}
                ]
            }
        }

        issues = _extract_snyk_issues(sample)
        self.assertEqual(len(issues), 2)
        self.assertTrue(any(item["id"] == "2" for item in issues))
        self.assertTrue(any(item["id"] == "3" for item in issues))

    def test_extracts_issue_like_list_at_root(self):
        sample = [
            {"id": "4", "title": "Root issue", "severity": "critical"}
        ]

        issues = _extract_snyk_issues(sample)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["id"], "4")
        self.assertEqual(issues[0]["severity"], "critical")

    def test_extracts_path_from_sarif_style_locations(self):
        sample = {
            'ruleId': 'javascript/HardcodedNonCryptoSecret/test',
            'locations': [
                {
                    'id': 0,
                    'physicalLocation': {
                        'artifactLocation': {'uri': 'test/server/verifySpec.ts', 'uriBaseId': '%SRCROOT%'},
                        'region': {'startLine': 263, 'endLine': 263, 'startColumn': 38, 'endColumn': 182},
                    },
                }
            ],
        }

        from scanners.snyk.plugin import _extract_snyk_path
        self.assertEqual(_extract_snyk_path(sample), 'test/server/verifySpec.ts')

    @patch.dict('os.environ', {'SNYK_TOKEN': 'token', 'SNYK_ORG': 'org'}, clear=True)
    @patch('scanners.snyk.plugin.requests.get')
    def test_snyk_api_plugin_enabled_and_scans(self, mock_get):
        mock_get.side_effect = [
            type('R', (), {'status_code': 200, 'json': lambda: {'projects': [{'id': 'proj1', 'name': 'repo-name'}]}}),
            type('R', (), {'status_code': 200, 'json': lambda: {'issues': [{'id': '5', 'title': 'API issue', 'severity': 'high'}]}}),
        ]

        plugin = SnykAPIPlugin()
        self.assertTrue(plugin.enabled)
        findings = plugin.scan('.')
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].id.startswith('snyk-api-'))
        self.assertLessEqual(len(findings[0].id), 20)

    @patch.dict('os.environ', {}, clear=True)
    @patch('scanners.snyk.plugin.shutil.which', return_value='/usr/bin/snyk')
    @patch('scanners.snyk.plugin.subprocess.run')
    def test_snyk_cli_plugin_enabled_and_scans(self, mock_run, mock_which):
        test_proc = type('P', (), {'stdout': json.dumps({'issues': [{'id': '6', 'title': 'CLI issue', 'severity': 'medium'}]}), 'stderr': '', 'returncode': 0})
        code_proc = type('P', (), {'stdout': json.dumps({'issues': [{'id': '7', 'title': 'Code issue', 'severity': 'low'}]}), 'stderr': '', 'returncode': 0})
        mock_run.side_effect = [test_proc, code_proc]

        plugin = SnykCLIPlugin()
        self.assertTrue(plugin.enabled)
        findings = plugin.scan('.')
        self.assertEqual(len(findings), 2)
        self.assertTrue(findings[0].id.startswith('snyk-'))
        self.assertLessEqual(len(findings[0].id), 16)
        self.assertTrue(findings[1].id.startswith('snyk-'))
        self.assertLessEqual(len(findings[1].id), 16)


if __name__ == "__main__":
    unittest.main()
