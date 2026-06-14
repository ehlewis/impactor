import unittest

from scanners.snyk.plugin import _extract_snyk_issues


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


if __name__ == "__main__":
    unittest.main()
