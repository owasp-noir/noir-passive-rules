import os
import re
import yaml
import pytest

def load_patterns():
    filepath = os.path.join(os.path.dirname(__file__), '../secrets/openai-api-key.yaml')
    with open(filepath, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    patterns = []
    for matcher in data.get('matchers', []):
        if matcher.get('type') == 'regex':
            patterns.extend(matcher.get('patterns', []))
    return patterns

@pytest.fixture
def patterns():
    return load_patterns()

def test_openai_api_key_patterns(patterns):
    assert len(patterns) > 0, "No regex patterns found in YAML file"

    # Valid test cases
    valid_cases = [
        "sk-" + "a" * 48,
        "sk-proj-" + "b" * 48,
        "key = 'sk-" + "c" * 48 + "'",
        "export OPENAI_API_KEY=sk-" + "d" * 48
    ]

    # Invalid test cases
    invalid_cases = [
        "sk-" + "a" * 47,  # Too short
        "sk-proj-" + "b" * 47, # Too short
        "something-else",
        "sk-invalid-char-" + "$" * 48, # Invalid characters
        "sk-proj-invalid-" + "%" * 48
    ]

    # We want to ensure that for a given valid key, at least one pattern matches.
    # The 'or' condition in matchers means if any regex matches, it's a hit.
    combined_regex = re.compile('|'.join(patterns))

    for case in valid_cases:
        assert combined_regex.search(case), f"Failed to match valid case: {case}"

    for case in invalid_cases:
        assert not combined_regex.search(case), f"Incorrectly matched invalid case: {case}"
