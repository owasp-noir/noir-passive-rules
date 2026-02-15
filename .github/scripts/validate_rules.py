#!/usr/bin/env python3
import yaml
import sys
import os
import glob

# Schema Definitions
REQUIRED_ROOT_KEYS = {
    'id': str,
    'info': dict,
    'matchers-condition': str,
    'matchers': list,
    'category': str,
    'techs': list
}

REQUIRED_INFO_KEYS = {
    'name': str,
    'author': list,
    'severity': str,
    'description': str,
    'reference': list
}

ALLOWED_SEVERITIES = ['critical', 'high', 'medium', 'low']
ALLOWED_CONDITIONS = ['or', 'and']
ALLOWED_MATCHER_TYPES = ['word', 'regex']
ALLOWED_CATEGORIES = ['secret']

def validate_rule(filepath):
    errors = []
    try:
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        return [f"YAML parsing error: {str(e)}"]

    if not isinstance(data, dict):
        return ["Root element must be a dictionary"]

    # Check root keys
    for key, expected_type in REQUIRED_ROOT_KEYS.items():
        if key not in data:
            errors.append(f"Missing required key: '{key}'")
        elif not isinstance(data[key], expected_type):
            errors.append(f"Key '{key}' must be of type {expected_type.__name__}, got {type(data[key]).__name__}")

    if errors:
        return errors

    # Validate 'info'
    info = data['info']
    for key, expected_type in REQUIRED_INFO_KEYS.items():
        if key not in info:
            errors.append(f"Missing key in 'info': '{key}'")
        elif not isinstance(info[key], expected_type):
            errors.append(f"Key 'info.{key}' must be of type {expected_type.__name__}, got {type(info[key]).__name__}")

    if 'severity' in info and info['severity'] not in ALLOWED_SEVERITIES:
        errors.append(f"Invalid severity: '{info['severity']}'. Allowed: {ALLOWED_SEVERITIES}")

    # Validate 'matchers-condition'
    if data['matchers-condition'] not in ALLOWED_CONDITIONS:
        errors.append(f"Invalid matchers-condition: '{data['matchers-condition']}'. Allowed: {ALLOWED_CONDITIONS}")

    # Validate 'category'
    if data['category'] not in ALLOWED_CATEGORIES:
        errors.append(f"Invalid category: '{data['category']}'. Allowed: {ALLOWED_CATEGORIES}")

    # Validate 'matchers'
    for i, matcher in enumerate(data['matchers']):
        if not isinstance(matcher, dict):
            errors.append(f"Matcher #{i} must be a dictionary")
            continue

        if 'type' not in matcher:
            errors.append(f"Matcher #{i} missing 'type'")
        elif matcher['type'] not in ALLOWED_MATCHER_TYPES:
            errors.append(f"Matcher #{i} has invalid type: '{matcher['type']}'. Allowed: {ALLOWED_MATCHER_TYPES}")

        if 'condition' not in matcher:
            errors.append(f"Matcher #{i} missing 'condition'")
        elif matcher['condition'] not in ALLOWED_CONDITIONS:
            errors.append(f"Matcher #{i} has invalid condition: '{matcher['condition']}'. Allowed: {ALLOWED_CONDITIONS}")

        if 'patterns' not in matcher:
            errors.append(f"Matcher #{i} missing 'patterns'")
        elif not isinstance(matcher['patterns'], list):
            errors.append(f"Matcher #{i} 'patterns' must be a list")

    return errors

def main():
    if len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        rules_dir = 'secrets'
        if not os.path.isdir(rules_dir):
            print(f"Directory '{rules_dir}' not found.")
            sys.exit(1)

        files = glob.glob(os.path.join(rules_dir, '*.yaml'))
        if not files:
            print(f"No YAML files found in '{rules_dir}'.")
            sys.exit(0)

    has_errors = False
    print(f"Validating {len(files)} rule files...")

    for filepath in files:
        file_errors = validate_rule(filepath)
        if file_errors:
            has_errors = True
            print(f"\n❌ {filepath}:")
            for err in file_errors:
                print(f"  - {err}")
        else:
            # print(f"✅ {filepath}")
            pass

    if has_errors:
        print("\nValidation failed with errors.")
        sys.exit(1)
    else:
        print("\nAll files passed validation! ✅")
        sys.exit(0)

if __name__ == "__main__":
    main()
