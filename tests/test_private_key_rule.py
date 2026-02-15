
import yaml
import re
import pytest
from pathlib import Path

def test_private_key_regex():
    # Use pathlib to construct the absolute path relative to the project root
    # Assuming tests/ is at the root and secrets/ is at the root.
    # __file__ is tests/test_private_key_rule.py
    # So .parent is tests/
    # .parent.parent is the root
    project_root = Path(__file__).parent.parent
    rule_file = project_root / "secrets" / "private-key.yaml"

    with open(rule_file, "r") as f:
        rule = yaml.safe_load(f)

    regex_patterns = []
    for matcher in rule.get("matchers", []):
        if matcher.get("type") == "regex":
            regex_patterns.extend(matcher.get("patterns", []))

    assert regex_patterns, "No regex patterns found in the rule file"

    # Positive test cases (should match at least one regex)
    positive_cases = [
        'PRIVATE_KEY = "my_secret_key"',
        "PRIVATE_KEY = 'another_secret'",
        "PRIVATE_KEY=secret_no_quotes",
        "PRIVATE_KEY   =   'spaced_secret'",
        """-----BEGIN PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD...
        -----END PRIVATE KEY-----""",
    ]

    # Negative test cases (should NOT match any regex)
    negative_cases = [
        'PUBLIC_KEY = "public_key"',
        'PRIVATE_KEY=""',  # Empty value without spaces, regex should fail
        "Just some random text",
        "API_KEY = '12345'",
    ]

    for case in positive_cases:
        matched = False
        for pattern in regex_patterns:
            if re.search(pattern, case):
                matched = True
                break
        assert matched, f"Failed to match positive case: {case}"

    for case in negative_cases:
        matched = False
        for pattern in regex_patterns:
            if re.search(pattern, case):
                matched = True
                break
        assert not matched, f"Incorrectly matched negative case: {case}"
