import re

RULES = {
    "hardcoded_secret": {
        # Captures variable name (group 1) and secret value (group 2)
        "pattern": r'(?i)([a-zA-Z0-9_]*(?:api_key|api_secret|password|passwd|secret|token|auth|credential|private_key|database_url|connection_string)[a-zA-Z0-9_]*)\s*=\s*["\']([^"\']{8,})["\']',
        "severity": "CRITICAL",
        "explanation": "Hardcoded secret detected — sensitive credentials exposed in source code.",
        "teach_back": (
            "Embedding passwords or API keys directly in code means anyone with repository "
            "access (including git history) can steal them and compromise your accounts."
        ),
        "remediation": "Store secrets in environment variables and load with os.getenv('VAR_NAME').",
        "penalty": 30
    },
    "sql_injection_risk": {
        # Detects f-string or % format string directly inside execute() calls
        "pattern": r"(?i)\.execute\s*\(\s*(?:f['\"]|['\"].*%\s*[({])",
        "severity": "HIGH",
        "explanation": "Potential SQL injection: user-controlled data interpolated directly into SQL query.",
        "teach_back": (
            "String-formatting SQL queries allows attackers to break out of the query context "
            "and execute arbitrary database commands."
        ),
        "remediation": "Use parameterised queries: cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))",
        "penalty": 20
    },
    "debug_mode_enabled": {
        "pattern": r"(?i)(?:app\.run|DEBUG)\s*[=(].*True",
        "severity": "MEDIUM",
        "explanation": "Debug mode is enabled — this exposes stack traces and internal state to end users.",
        "teach_back": "Running a web server in debug mode leaks internal code paths and enables remote code execution in some frameworks.",
        "remediation": "Set DEBUG=False in production. Load from environment: DEBUG=os.getenv('DEBUG', 'False') == 'True'",
        "penalty": 10
    }
}

# Values that are clearly placeholders — skip these to avoid false positives
DUMMY_KEYWORDS = [
    'test', 'dummy', 'example', 'placeholder', 'your_', 'insert_',
    'changeme', 'xxxxxxx', '12345', 'abc123', 'none', 'null', 'todo'
]


def is_dummy_data(value: str) -> bool:
    """Returns True if the detected secret value is clearly a placeholder."""
    val_lower = value.lower()
    if len(value) < 6:
        return True
    return any(keyword in val_lower for keyword in DUMMY_KEYWORDS)


def scan_file_static(file_path: str, code_lines: list) -> list:
    issues = []

    # Skip test files entirely — they intentionally use fake secrets
    if "test" in file_path.lower() or file_path.endswith("_test.py"):
        return issues

    for line_number, line in enumerate(code_lines):
        # Skip comment lines
        stripped = line.strip()
        if stripped.startswith('#'):
            continue

        for rule_name, rule_data in RULES.items():
            match = re.search(rule_data["pattern"], line)
            if not match:
                continue

            if rule_name == "hardcoded_secret":
                secret_value = match.group(2)
                if is_dummy_data(secret_value):
                    continue  # Safe placeholder — skip
                var_name = match.group(1)
                fixed_code = f"{var_name} = os.getenv('{var_name.upper()}')  # SECURE: Loaded from environment"
            else:
                var_name = None
                fixed_code = rule_data.get("remediation", "See remediation note.")

            issues.append({
                "file": file_path,
                "line": line_number + 1,
                "code": line.strip(),
                "severity": rule_data["severity"],
                "explanation": rule_data["explanation"],
                "teach_back": rule_data["teach_back"],
                "remediation": rule_data["remediation"],
                "fixed_code": fixed_code,
                "penalty": rule_data["penalty"]
            })

    return issues
