import yaml
import re
import pytest
import os

def load_rule(filepath):
    with open(filepath, 'r') as f:
        return yaml.safe_load(f)

def test_gemini_api_key_regex():
    # Resolve the path relative to this test file
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rule_path = os.path.join(base_dir, 'secrets/gemini-api-key.yaml')

    rule = load_rule(rule_path)
    patterns = []
    for matcher in rule['matchers']:
        if matcher['type'] == 'regex':
            patterns.extend(matcher['patterns'])

    assert len(patterns) > 0, "No regex patterns found in rule"

    # Positive test cases (should match)
    valid_keys = [
        "AIzaSy" + "a" * 33,
        "AIzaSy" + "A" * 33,
        "AIzaSy" + "0" * 33,
        "AIzaSy" + "-" * 33,
        "AIzaSy" + "_" * 33,
        "AIzaSy" + "AbC123-_" * 4 + "a", # 33 chars
        "some prefix " + "AIzaSy" + "a" * 33 + " some suffix", # Embedded
    ]

    # Negative test cases (should NOT match)
    invalid_keys = [
        "AIzaSy" + "a" * 32,      # Too short (38 chars total)
        "AIzaSx" + "a" * 33,      # Wrong prefix
        "AIzaSy" + "!" * 33,      # Invalid char
        "AIzaSy" + " " * 33,      # Invalid char (space)
        "AIzaS" + "a" * 33,       # Wrong prefix structure (missing 'y')
    ]

    for pattern in patterns:
        regex = re.compile(pattern)

        # Test valid keys
        for key in valid_keys:
            assert regex.search(key), f"Failed to match valid key: '{key}' with pattern: '{pattern}'"

        # Test invalid keys
        for key in invalid_keys:
            match = regex.search(key)
            assert not match, f"Unexpectedly matched invalid key: '{key}' with pattern: '{pattern}'"
