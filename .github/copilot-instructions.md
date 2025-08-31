# OWASP Noir Passive Rules Repository

**Always reference these instructions first and only fallback to search or bash commands when you encounter unexpected information that does not match the info here.**

This repository contains YAML-based passive scan rules for OWASP Noir, a security testing tool that identifies attack surfaces through static analysis. These rules define patterns to detect secrets, API keys, tokens, and other sensitive data in source code.

## Working Effectively

### Bootstrap and Validate the Repository
- This is a **data repository** containing YAML rule definitions - there is NO traditional build process
- Validate YAML syntax: `yamllint -c .github/yamllint.yml secrets/*.yaml` -- takes < 1 second, NEVER needs timeout
- Check all secret rule files: `ls -la secrets/` (should show 13 .yaml files)
- **CRITICAL**: Always ensure YAML files end with exactly one newline character or yamllint will fail

### Development Workflow
- **ALWAYS** run `yamllint -c .github/yamllint.yml secrets/*.yaml` before committing changes
- **ALWAYS** run `yamllint -c .github/yamllint.yml <filename>` when creating or modifying individual rule files
- Test rule syntax immediately after making changes: `yamllint -c .github/yamllint.yml secrets/your-file.yaml`
- **NEVER CANCEL** yamllint commands - they complete in under 1 second

### Creating New Rules
- Copy an existing rule file as template: `cp secrets/github-token.yaml secrets/new-rule.yaml`
- Edit the rule following the YAML schema shown in existing files
- **REQUIRED fields**: id, info (name, author, severity, description, reference), matchers-condition, matchers, category, techs
- **ALWAYS** end files with exactly one newline character
- Validate immediately: `yamllint -c .github/yamllint.yml secrets/new-rule.yaml`

### Modifying Existing Rules
- Edit files directly in the `secrets/` directory
- **ALWAYS** validate after changes: `yamllint -c .github/yamllint.yml secrets/modified-file.yaml`
- Common modifications: adding new patterns, updating regex, changing severity levels

## Validation Scenarios

**ALWAYS run these validation steps after making any changes:**

1. **Basic YAML Syntax Validation**:
   ```bash
   yamllint -c .github/yamllint.yml secrets/*.yaml
   ```
   Expected: No output, exit code 0

2. **Individual File Validation**:
   ```bash
   yamllint -c .github/yamllint.yml secrets/your-modified-file.yaml
   ```
   Expected: No output, exit code 0

3. **Test New Rule Creation**:
   ```bash
   # Create a test rule
   cp secrets/github-token.yaml /tmp/test-rule.yaml
   # Modify it (change id, patterns, etc.)
   # Validate it
   yamllint -c .github/yamllint.yml /tmp/test-rule.yaml
   ```

4. **Test Error Detection**:
   ```bash
   # Create invalid YAML to ensure linting catches errors
   echo "    - bad indentation" >> /tmp/bad-file.yaml
   yamllint -c .github/yamllint.yml /tmp/bad-file.yaml
   ```
   Expected: Syntax error reported, exit code 1

## CI/CD Workflows

### YAML Lint Workflow (.github/workflows/yamllint.yml)
- **Triggers**: Pull requests to main branch
- **Action**: Runs `yamllint` on all files in `secrets/*.yaml`
- **Timing**: < 5 seconds, NEVER needs timeout
- **CRITICAL**: This will fail if any YAML file has syntax errors or formatting issues

### CI Workflow (.github/workflows/ci.yml) 
- **Triggers**: Push to main branch, manual dispatch
- **Actions**: Updates CONTRIBUTORS.svg and revision timestamp
- **Timing**: < 30 seconds, NEVER needs timeout

### Labeler Workflow
- **Triggers**: Pull requests
- **Action**: Auto-labels PRs based on changed files
- **Labels**: `rule-secrets` for changes in secrets/, `ci` for changes in .github/

## Common Tasks

### Repository Structure
```
.
├── .github/
│   ├── workflows/          # CI/CD workflows
│   ├── yamllint.yml       # YAML linting configuration
│   └── labeler.yml        # PR auto-labeling rules
├── secrets/               # Rule definition files (main content)
│   ├── aws-access-key.yaml
│   ├── github-token.yaml
│   ├── openai-api-key.yaml
│   └── ...               # 13 rule files
├── README.md
├── LICENSE
├── revision              # Auto-updated timestamp
└── CONTRIBUTORS.svg      # Auto-generated contributor list
```

### Secret Rule File Schema
```yaml
---
id: unique-rule-id
info:
  name: Human readable name
  author: [author names]
  severity: critical|high|medium|low
  description: Description of what this rule detects
  reference: ['reference urls']
matchers-condition: or|and
matchers:
  - type: word|regex
    patterns: [pattern1, pattern2]
    condition: or|and
category: secret
techs: ['*']
```

### Sample Rule Commands
```bash
# List all rule files
ls -la secrets/

# Count rules
ls secrets/*.yaml | wc -l

# View rule structure
cat secrets/github-token.yaml

# Validate all rules
yamllint -c .github/yamllint.yml secrets/*.yaml

# Validate specific rule
yamllint -c .github/yamllint.yml secrets/aws-access-key.yaml
```

## Key Points for Agents

- **NO BUILD PROCESS**: This repository contains only YAML data files, no compilation needed
- **PRIMARY VALIDATION**: YAML syntax checking via yamllint - this is the ONLY "build" step
- **TIMING**: All operations complete in under 5 seconds, never set timeouts > 30 seconds
- **FILE ENDINGS**: YAML files MUST end with newline character or yamllint fails
- **CHANGES**: Primarily involve editing YAML rule definitions in the `secrets/` directory
- **TESTING**: Create test files in `/tmp/` directory to avoid committing temporary files
- **INTEGRATION**: These rules are consumed by the main OWASP Noir tool (written in Crystal)
- **PURPOSE**: Define patterns to detect secrets/credentials/tokens in source code during security scans

## Troubleshooting

**YAML Lint Failures**:
- Check for missing newline at end of file OR too many blank lines
- Verify proper YAML indentation (2 spaces, no tabs)
- Ensure all required fields are present
- Check for syntax errors in regex patterns

**File Not Validating**:
- Files should end with exactly one newline, check with: `tail -1 filename.yaml | od -c`
- Check indentation with: `cat -A filename.yaml`
- Compare with working example: `diff secrets/github-token.yaml your-file.yaml`

**CI Workflow Failures**:
- Always check YAML lint status first
- Ensure branch is up to date with main
- Verify all files in secrets/ directory validate

Remember: This is a simple repository focused on rule definitions. The complexity is in writing effective detection patterns, not in build/deployment processes.