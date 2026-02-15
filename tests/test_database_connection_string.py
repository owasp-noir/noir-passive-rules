import unittest
import yaml
import re
import os

class TestDatabaseConnectionStringRegex(unittest.TestCase):
    def setUp(self):
        # Assuming the test is run from the project root
        self.yaml_file = 'secrets/database-connection-string.yaml'
        if not os.path.exists(self.yaml_file):
            # Fallback for running from tests/ directory
            self.yaml_file = '../secrets/database-connection-string.yaml'

        with open(self.yaml_file, 'r') as f:
            self.data = yaml.safe_load(f)

        self.regex_patterns = []
        for matcher in self.data.get('matchers', []):
            if matcher.get('type') == 'regex':
                patterns = matcher.get('patterns', [])
                if isinstance(patterns, list):
                    self.regex_patterns.extend(patterns)
                elif isinstance(patterns, str):
                    self.regex_patterns.append(patterns)

    def test_positive_matches(self):
        """Test strings that SHOULD be matched by the regex."""
        positive_cases = [
            "mysql://user:pass@localhost:3306/db",
            "mysql://admin:1234@127.0.0.1:3306/mydb",
            "mysql://user:pass@example.com:3306/db",
            "mysql://u1:p2@h3:4/d5",
        ]

        for pattern in self.regex_patterns:
            compiled_pattern = re.compile(pattern)
            for case in positive_cases:
                with self.subTest(pattern=pattern, case=case):
                    self.assertTrue(compiled_pattern.search(case), f"Pattern '{pattern}' should match '{case}'")

    def test_negative_matches(self):
        """Test strings that SHOULD NOT be matched by the regex."""
        negative_cases = [
            "postgres://user:pass@localhost:5432/db",
            "mysql://user@localhost:3306/db", # Missing password
            "mysql://:pass@localhost:3306/db", # Missing user
            "mysql://user:pass@:3306/db", # Missing host
            "mysql://user:pass@localhost:/db", # Missing port
            "mysql://user:pass@localhost:3306/", # Missing db name
            "http://google.com",
            "random text",
        ]

        for pattern in self.regex_patterns:
            compiled_pattern = re.compile(pattern)
            for case in negative_cases:
                with self.subTest(pattern=pattern, case=case):
                    self.assertFalse(compiled_pattern.search(case), f"Pattern '{pattern}' should NOT match '{case}'")

if __name__ == '__main__':
    unittest.main()
