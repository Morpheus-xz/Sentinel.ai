import re

# Upgraded CVE Database with exact auto-fixes
CVE_DATABASE = {
    "requests": {
        "severity": "HIGH",
        "explanation": "Vulnerability in older requests library (CVE-2023-32681) leaking proxy credentials.",
        "remediation": "Upgrade to requests>=2.31.0 in your requirements.txt.",
        "fixed_code": "requests>=2.31.0",
        "penalty": 15
    },
    "urllib3": {
        "severity": "MEDIUM",
        "explanation": "Vulnerable to HTTP response splitting (CVE-2020-26137).",
        "remediation": "Upgrade to urllib3>=1.25.10.",
        "fixed_code": "urllib3>=1.25.10",
        "penalty": 10
    },
    "express": {
        "severity": "CRITICAL",
        "explanation": "Known Remote Code Execution (RCE) vulnerability.",
        "remediation": "Upgrade to express>=4.18.0 in package.json.",
        "fixed_code": "\"express\": \"^4.18.0\"",
        "penalty": 25
    }
}


def generate_sbom_and_scan(file_path: str, code_lines: list) -> list:
    """Parses dependency files line-by-line to extract the exact line number of vulnerable packages."""
    issues = []

    for line_number, line in enumerate(code_lines):
        line_str = line.strip().lower()
        if not line_str:
            continue

        # Check Python dependencies
        if file_path.endswith("requirements.txt"):
            for pkg_name, vuln in CVE_DATABASE.items():
                # Regex to match the package name exactly at the start of the line
                if re.match(rf"^{pkg_name}(?:[=<>!~]|$)", line_str):
                    issues.append({
                        "file": file_path,
                        "line": line_number + 1,  # THE EXACT LINE NUMBER
                        "code": line.strip(),
                        "severity": vuln["severity"],
                        "explanation": vuln["explanation"],
                        "teach_back": "Supply chain attacks target outdated third-party libraries to infiltrate secure enterprise systems.",
                        "remediation": vuln["remediation"],
                        "fixed_code": f"{vuln['fixed_code']}  # SECURE: Upgraded to patched version",
                        "penalty": vuln["penalty"]
                    })

        # Check Node.js dependencies
        elif file_path.endswith("package.json"):
            for pkg_name, vuln in CVE_DATABASE.items():
                if f'"{pkg_name}"' in line_str:
                    issues.append({
                        "file": file_path,
                        "line": line_number + 1,  # THE EXACT LINE NUMBER
                        "code": line.strip(),
                        "severity": vuln["severity"],
                        "explanation": vuln["explanation"],
                        "teach_back": "Supply chain attacks target outdated third-party libraries to infiltrate secure enterprise systems.",
                        "remediation": vuln["remediation"],
                        "fixed_code": f"\"{pkg_name}\": {vuln['fixed_code']}, // SECURE: Upgraded to patched version",
                        "penalty": vuln["penalty"]
                    })

    return issues