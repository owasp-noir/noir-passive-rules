import pytest
import yaml
import re
from pathlib import Path

# Load the YAML file
SECRETS_DIR = Path(__file__).parent.parent / "secrets"
GITHUB_TOKEN_YAML = SECRETS_DIR / "github-token.yaml"

@pytest.fixture
def github_token_rules():
    with open(GITHUB_TOKEN_YAML, "r") as f:
        return yaml.safe_load(f)

def test_github_token_regex_patterns(github_token_rules):
    # Extract regex patterns
    matchers = github_token_rules.get("matchers", [])
    regex_matcher = next((m for m in matchers if m["type"] == "regex"), None)
    assert regex_matcher is not None, "No regex matcher found in YAML"

    patterns = regex_matcher.get("patterns", [])
    assert len(patterns) > 0, "No regex patterns found"

    # Test cases mapping patterns to examples
    # Note: We check if the pattern is present in the YAML file first

    expected_patterns = {
        r"github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9]{59}": {
            "positive": [
                "github_pat_11AAAAAAA1111111111111_11111111111111111111111111111111111111111111111111111111111",
                "github_pat_ABCDEFGHIJKLMNOPQRSTUV_12345678901234567890123456789012345678901234567890123456789",
            ],
            "negative": [
                "github_pat_11AAAAAAA111111111111_11111111111111111111111111111111111111111111111111111111111", # too short first part
                "github_pat_11AAAAAAA1111111111111_1111111111111111111111111111111111111111111111111111111111", # too short second part
                "github_pat_11AAAAAAA1111111111111-11111111111111111111111111111111111111111111111111111111111", # wrong separator
            ]
        },
        r"ghp_[A-Za-z0-9]{36}": {
            "positive": [
                "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
                "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
            ],
            "negative": [
                "ghp_1234567890abcdefghijklmnopqrstuvwxy", # 35 chars
                "ghp_1234567890abcdefghijklmnopqrstuvwxyz1", # 37 chars
                "gha_1234567890abcdefghijklmnopqrstuvwxyz", # wrong prefix
            ]
        },
        r"gho_[A-Za-z0-9]{36}": {
            "positive": [
                "gho_1234567890abcdefghijklmnopqrstuvwxyz",
            ],
            "negative": [
                "gho_1234567890abcdefghijklmnopqrstuvwxy",
                "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            ]
        },
        r"ghu_[A-Za-z0-9]{36}": {
            "positive": [
                "ghu_1234567890abcdefghijklmnopqrstuvwxyz",
            ],
            "negative": [
                "ghu_1234567890abcdefghijklmnopqrstuvwxy",
            ]
        },
        r"ghs_[A-Za-z0-9]{36}": {
            "positive": [
                "ghs_1234567890abcdefghijklmnopqrstuvwxyz",
            ],
            "negative": [
                "ghs_1234567890abcdefghijklmnopqrstuvwxy",
            ]
        },
        r"ghr_[A-Za-z0-9]{36}": {
            "positive": [
                "ghr_1234567890abcdefghijklmnopqrstuvwxyz",
            ],
            "negative": [
                "ghr_1234567890abcdefghijklmnopqrstuvwxy",
            ]
        },
    }

    # Verify all expected patterns are in the YAML
    for pattern_str, cases in expected_patterns.items():
        assert pattern_str in patterns, f"Pattern {pattern_str} not found in YAML"

        regex = re.compile(pattern_str)

        for pos in cases["positive"]:
            assert regex.fullmatch(pos), f"Failed to match valid token: {pos} with pattern {pattern_str}"

        for neg in cases["negative"]:
            assert not regex.fullmatch(neg), f"Incorrectly matched invalid token: {neg} with pattern {pattern_str}"

    # Verify we tested all patterns in the YAML (optional, but good for coverage)
    for p in patterns:
        assert p in expected_patterns, f"Pattern {p} in YAML is not covered by tests"
