# AGENTS.md

This file provides instructions for AI coding agents working on the **OWASP Noir Passive Rules** repository.

## Repository Overview

This repository contains YAML-based passive scan rules consumed by [OWASP Noir](https://github.com/owasp-noir/noir). Each rule defines patterns (keywords and regular expressions) to detect secrets, API keys, tokens, and other sensitive data in source code during static analysis.

### Directory Layout

```
.
├── secrets/                 # YAML rule definition files (main content)
├── spec/                    # Crystal test suite
│   ├── spec_helper.cr       # Rule parser & matcher engine
│   └── secrets_spec.cr      # Tests for every rule
├── .github/
│   ├── workflows/
│   │   ├── ci.yml           # Push-to-main: Crystal spec, contributors, revision
│   │   └── yamllint.yml     # PR: YAML lint check
│   ├── yamllint.yml         # yamllint configuration
│   └── labeler.yml          # PR auto-labeling rules
├── AGENTS.md                # ← You are here
├── README.md
├── LICENSE
├── revision                 # Auto-updated timestamp
└── CONTRIBUTORS.svg         # Auto-generated contributor list
```

## Rule File Schema

Every rule file lives under `secrets/` and follows this structure:

```yaml
---
id: unique-rule-id
info:
  name: Human readable name
  author: [author names]
  severity: critical|high|medium|low
  description: Description of what this rule detects
  reference: ['https://reference-url']
matchers-condition: or|and
matchers:
  - type: word
    patterns: [KEYWORD_ONE, KEYWORD_TWO]
    condition: or|and
  - type: regex
    patterns:
      - 'regex_pattern_here'
    condition: or|and
category: secret
techs: ['*']
```

### Required Fields

| Field | Description |
|---|---|
| `id` | Unique identifier, lowercase with hyphens (e.g. `github-token`) |
| `info.name` | Human-readable rule name |
| `info.author` | List of authors |
| `info.severity` | One of: `critical`, `high`, `medium`, `low` |
| `info.description` | What the rule detects |
| `info.reference` | List of reference URLs (use `['']` if none) |
| `matchers-condition` | How multiple matcher blocks combine: `or` or `and` |
| `matchers` | At least one matcher block with `type`, `patterns`, `condition` |
| `category` | Always `secret` |
| `techs` | Always `['*']` for language-agnostic rules |

### Matcher Types

- **`word`** — Exact substring match. Use for environment variable names, fixed prefixes, and URL stems.
- **`regex`** — Regular expression match. Use for structured token formats with known character classes and lengths.

## Adding a New Rule — Step by Step

### 1. Create the YAML Rule File

Copy an existing rule as a starting point:

```bash
cp secrets/github-token.yaml secrets/your-new-rule.yaml
```

Edit the file. Replace `id`, `info`, and `matchers` with your new rule's content.

**CRITICAL**: The file MUST end with exactly one newline character.

### 2. Validate YAML Syntax

```bash
yamllint -c .github/yamllint.yml secrets/your-new-rule.yaml
```

Expected: no output, exit code 0. This completes in under 1 second.

### 3. Add Tests to `spec/secrets_spec.cr`

Every rule **must** have corresponding tests. Add a new `describe` block for your rule inside the `"Passive Secret Rules"` describe block. Each rule needs at minimum:

- **Positive tests** — one per word pattern and one per regex pattern, confirming `rule.match?` returns `true`.
- **Negative tests** — at least one benign string that must NOT match, confirming `rule.match?` returns `false`.
- **Boundary tests** — strings that are close to matching but should not (e.g. too short, wrong prefix).

Example structure:

```crystal
describe "your-new-rule" do
  rule = Rule.from_file(File.join(SECRETS_DIR, "your-new-rule.yaml"))

  it "matches YOUR_ENV_VAR keyword" do
    rule.match?("YOUR" + "_ENV_VAR=something").should be_true
  end

  it "matches token regex pattern" do
    rule.match?("pre" + "fix_" + "A" * 40).should be_true
  end

  it "does not match unrelated text" do
    rule.match?("This is normal text with no secrets").should be_false
  end

  it "does not match too-short token" do
    rule.match?("pre" + "fix_short").should be_false
  end
end
```

### 4. Run Tests

```bash
crystal spec/secrets_spec.cr
```

All tests must pass with 0 failures.

### 5. Final Validation

```bash
yamllint -c .github/yamllint.yml secrets/*.yaml
crystal spec/secrets_spec.cr
```

Both commands must succeed before committing.

## ⚠️ GitHub Push Protection — CRITICAL

GitHub Push Protection scans pushed code for patterns that look like real secrets. Since this repository tests secret detection patterns, **test strings can trigger push protection and block your push entirely**.

### The Problem

If you write a test string like this:

```crystal
# ❌ BAD — GitHub will block the push
rule.match?("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij").should be_true
```

GitHub's static scanner sees `ghp_ABCDEF...` as a real GitHub Personal Access Token and rejects the push with error `GH013: Repository rule violations found`.

### The Solution — Runtime String Assembly

**Never write a complete secret-like literal in source code.** Instead, assemble it at runtime using string concatenation so no single string literal matches a known secret pattern.

```crystal
# ✅ GOOD — Assembled at runtime, invisible to static scanners
rule.match?("gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghij").should be_true
```

### Using the `FakeSecrets` Module

`spec/secrets_spec.cr` contains a `FakeSecrets` module that centralises all fake secret strings. When adding new rules:

1. **Add a new method** to `FakeSecrets` that builds the fake token with concatenation:

```crystal
module FakeSecrets
  # ... existing methods ...

  def self.your_new_token
    "your_pre" + "fix_" + "A" * 40
  end
end
```

2. **Use it in tests**:

```crystal
it "matches token regex" do
  rule.match?(FakeSecrets.your_new_token).should be_true
end
```

### What to Split

Split the string at the **signature prefix** that secret scanners look for. Common split points:

| Secret Type | Literal to Avoid | How to Split |
|---|---|---|
| GitHub PAT | `ghp_XXXX` | `"gh" + "p_" + "XXXX"` |
| GitLab PAT | `glpat-XXXX` | `"glp" + "at-" + "XXXX"` |
| AWS Key ID | `AKIAXXXX` | `"AKI" + "AXXXX"` |
| OpenAI Key | `sk-XXXX` | `"sk" + "-" + "XXXX"` |
| Stripe Key | `sk_live_XXXX` | `"sk" + "_live_" + "XXXX"` |
| Webhook URL | `https://hooks.slack.com/services/TXXX` | `"https://hooks" + ".slack.com/services/" + "TXXX"` |
| PEM Header | `-----BEGIN RSA PRIVATE KEY-----` | `"-----BEGIN " + "RSA PRIVATE KEY-----"` |
| Environment variable | `AWS_SECRET_ACCESS_KEY` | `"AWS_SECRET" + "_ACCESS_KEY"` |

**Rule of thumb**: if `grep -E 'known_prefix_pattern'` would match your test string, it needs to be split.

### Verification Before Push

Run this command to check for accidental secret-like literals in test files:

```bash
grep -rnE '(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghu_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|ghr_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{15,}|glptt-[A-Za-z0-9_-]{15,}|sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{40,}|AIzaSy[A-Za-z0-9\-_]{30,}|xai-[A-Za-z0-9]{80,})' spec/
```

Expected: **no output** (exit code 1). If anything matches, split the offending string.

## Test Architecture

### `spec/spec_helper.cr`

Defines two structs:

- **`Matcher`** — Represents one matcher block. Supports `word` (substring match) and `regex` (Regex match) types with `and`/`or` condition logic.
- **`Rule`** — Represents a full YAML rule. Parses via `Rule.from_file(path)`, evaluates via `Rule#match?(text)`.

### `spec/secrets_spec.cr`

Organised into sections:

| Section | Purpose |
|---|---|
| **YAML structure validation** | Validates every `.yaml` file has all required fields |
| **Regex validity** | Ensures all regex patterns compile without error |
| **Per-rule matching tests** | Positive, negative, and boundary tests for each rule |
| **Cross-rule false positive checks** | Confirms benign strings match zero rules |
| **Matchers-condition semantics** | Validates structural conventions (all use `or`, category `secret`) |
| **Severity validation** | Ensures severity is one of the four allowed values |

The YAML structure and regex validity tests are **automatically applied to all rule files** via `Dir.glob`, so new rules get basic validation for free. But per-rule matching tests must be written manually.

## CI Workflows

### On Push to `main` (`.github/workflows/ci.yml`)

| Job | What It Does |
|---|---|
| `test` | Installs Crystal, runs `crystal spec/secrets_spec.cr` |
| `contributors` | Updates `CONTRIBUTORS.svg` |
| `revision` | Updates `revision` timestamp and pushes |

### On Pull Request (`.github/workflows/yamllint.yml`)

Runs `yamllint` against all `secrets/*.yaml` files.

## Checklist for New Patterns

Use this checklist every time you add or modify a rule:

- [ ] YAML file created/modified in `secrets/` with all required fields
- [ ] `yamllint -c .github/yamllint.yml secrets/your-rule.yaml` passes
- [ ] File ends with exactly one newline character
- [ ] `FakeSecrets` method added in `spec/secrets_spec.cr` using string concatenation
- [ ] `describe` block added with positive, negative, and boundary tests
- [ ] All test strings use runtime assembly — no complete secret literals
- [ ] `grep -rnE '<secret patterns>' spec/` returns no matches
- [ ] `crystal spec/secrets_spec.cr` passes with 0 failures
- [ ] `yamllint -c .github/yamllint.yml secrets/*.yaml` passes for all files

## Common Pitfalls

| Pitfall | Fix |
|---|---|
| YAML file missing trailing newline | Ensure exactly one `\n` at end of file |
| YAML indentation with tabs | Use 2 spaces, never tabs |
| Regex special chars unescaped in YAML | Wrap regex in single quotes: `'pattern'` |
| Push rejected by GitHub Push Protection | Split secret-like test strings with `+` concatenation |
| Test passes locally but fails in CI | Ensure `spec/spec_helper.cr` and rule file are both committed |
| New rule not covered by structure tests | Structure/regex tests auto-discover via glob — just ensure the file is in `secrets/` |
| New rule missing matching tests | Always add a dedicated `describe` block with positive and negative cases |