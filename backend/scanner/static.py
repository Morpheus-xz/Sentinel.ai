import re

RULES = {
    "hardcoded_secret": {
        # This updated regex grabs the full variable name (e.g., aws_production_token)
        "pattern": r"(?i)([a-zA-Z0-9_]*(?:api_key|password|secret|token)[a-zA-Z0-9_]*)\s*=\s*['\"]([^'\"]+)['\"]",
        "severity": "CRITICAL",
        "explanation": "Hardcoded secret exposes sensitive credentials.",
        "teach_back": "When you put passwords or API keys directly in your code, anyone who views your code can steal them and compromise your accounts.",
        "remediation": "Store secrets in environment variables (e.g., os.getenv('API_KEY')).",
        "penalty": 30
    }
}


def is_dummy_data(value: str) -> bool:
    """ZERO ASSUMPTIONS: Checks if the found secret is just a placeholder."""
    dummy_keywords = ['test', 'dummy', 'example', 'your_', 'insert_', '12345', 'xxx']
    val_lower = value.lower()
    return any(keyword in val_lower for keyword in dummy_keywords) or len(value) < 5


def scan_file_static(file_path: str, code_lines: list) -> list:
    issues = []
    # Ignore test files entirely to prevent false positives
    if "test" in file_path.lower():
        return issues

    for line_number, line in enumerate(code_lines):
        for rule_name, rule_data in RULES.items():
            match = re.search(rule_data["pattern"], line)
            if match:
                # Group 2 in our regex is the actual value of the secret
                secret_value = match.group(2)

                # VERIFICATION: Is this just test data?
                if rule_name == "hardcoded_secret" and is_dummy_data(secret_value):
                    continue  # Safe placeholder. Skip it.

                # Build a dynamic fix based on the exact variable name found
                var_name = match.group(1)
                fixed_code = f"{var_name} = os.getenv('{var_name.upper()}')  # SECURE: Loaded from environment"

                issues.append({
                    "file": file_path,
                    "line": line_number + 1,  # EXACT LINE NUMBER
                    "code": line.strip(),
                    "severity": rule_data["severity"],
                    "explanation": rule_data["explanation"],
                    "teach_back": rule_data["teach_back"],
                    "remediation": rule_data["remediation"],
                    "fixed_code": fixed_code,
                    "penalty": rule_data["penalty"]
                })

    return issues