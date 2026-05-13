import re
from packaging.version import Version, InvalidVersion

# CVE Database with minimum SAFE version thresholds
CVE_DATABASE = {
    "requests": {
        "safe_version": "2.31.0",
        "severity": "HIGH",
        "cve_id": "CVE-2023-32681",
        "explanation": "Versions below 2.31.0 are vulnerable to proxy credential leakage (CVE-2023-32681).",
        "remediation": "Upgrade to requests>=2.31.0 in your requirements.txt.",
        "fixed_code": "requests>=2.31.0",
        "penalty": 15
    },
    "urllib3": {
        "safe_version": "1.25.10",
        "severity": "MEDIUM",
        "cve_id": "CVE-2020-26137",
        "explanation": "Versions below 1.25.10 are vulnerable to HTTP response splitting (CVE-2020-26137).",
        "remediation": "Upgrade to urllib3>=1.25.10.",
        "fixed_code": "urllib3>=1.25.10",
        "penalty": 10
    },
    "express": {
        "safe_version": "4.18.0",
        "severity": "CRITICAL",
        "cve_id": "CVE-2022-24999",
        "explanation": "Versions below 4.18.0 have a known Remote Code Execution vulnerability (CVE-2022-24999).",
        "remediation": "Upgrade to express>=4.18.0 in package.json.",
        "fixed_code": '"express": "^4.18.0"',
        "penalty": 25
    },
    "pillow": {
        "safe_version": "9.3.0",
        "severity": "HIGH",
        "cve_id": "CVE-2022-45198",
        "explanation": "Versions below 9.3.0 are vulnerable to buffer overflow in image parsing (CVE-2022-45198).",
        "remediation": "Upgrade to Pillow>=9.3.0.",
        "fixed_code": "Pillow>=9.3.0",
        "penalty": 15
    },
    "cryptography": {
        "safe_version": "41.0.0",
        "severity": "HIGH",
        "cve_id": "CVE-2023-23931",
        "explanation": "Versions below 41.0.0 have a Bleichenbacher timing oracle vulnerability (CVE-2023-23931).",
        "remediation": "Upgrade to cryptography>=41.0.0.",
        "fixed_code": "cryptography>=41.0.0",
        "penalty": 15
    }
}


def _parse_pinned_version(line_str: str, pkg_name: str):
    """Extracts operator and version string from a requirements line."""
    match = re.search(
        rf"^{re.escape(pkg_name)}\s*([=<>!~]{{1,2}})\s*([\d][^\s,;#]*)",
        line_str, re.IGNORECASE
    )
    if match:
        return match.group(1), match.group(2)
    return None, None


def _is_version_vulnerable(operator: str, version_str: str, safe_version: str) -> bool:
    """
    Real semantic version comparison.
    Only flags a package if its pinned version is STRICTLY below the safe threshold.
    """
    try:
        pinned = Version(version_str)
        safe = Version(safe_version)
        if operator in ("==", "<=", ">=", "~=", "!="):
            # For ==, >=, <=: check if the pinned version is below safe
            # For >=: if minimum requirement is already >= safe, it's fine
            if operator == ">=":
                return pinned < safe
            return pinned < safe
        return pinned < safe
    except InvalidVersion:
        return False  # Never false-positive on unparseable versions


def generate_sbom_and_scan(file_path: str, code_lines: list) -> list:
    """
    Parses dependency files with SEMANTIC VERSION COMPARISON.
    Never flags a package that is already at or above the safe version.
    """
    issues = []

    for line_number, line in enumerate(code_lines):
        line_str = line.strip()
        if not line_str or line_str.startswith('#'):
            continue

        # Python requirements.txt
        if file_path.endswith("requirements.txt"):
            for pkg_name, vuln in CVE_DATABASE.items():
                if not re.match(rf"^{re.escape(pkg_name)}\s*([=<>!~]|$)", line_str, re.IGNORECASE):
                    continue

                operator, version_str = _parse_pinned_version(line_str, pkg_name)

                if version_str is None:
                    # No version pin — advisory LOW severity only
                    issues.append({
                        "file": file_path,
                        "line": line_number + 1,
                        "code": line.strip(),
                        "severity": "LOW",
                        "explanation": f"No version pinned for '{pkg_name}'. Known CVE exists: {vuln['cve_id']}.",
                        "teach_back": "Always pin dependency versions to prevent insecure installs.",
                        "remediation": vuln["remediation"],
                        "fixed_code": f"{vuln['fixed_code']}  # SECURE: Pinned to safe version",
                        "penalty": 5
                    })
                    continue

                if _is_version_vulnerable(operator, version_str, vuln["safe_version"]):
                    issues.append({
                        "file": file_path,
                        "line": line_number + 1,
                        "code": line.strip(),
                        "severity": vuln["severity"],
                        "explanation": f"[{vuln['cve_id']}] {vuln['explanation']}",
                        "teach_back": "Supply chain attacks target outdated third-party libraries.",
                        "remediation": vuln["remediation"],
                        "fixed_code": f"{vuln['fixed_code']}  # SECURE: Upgraded to patched version",
                        "penalty": vuln["penalty"]
                    })

        # Node.js package.json
        elif file_path.endswith("package.json"):
            for pkg_name, vuln in CVE_DATABASE.items():
                if f'"{pkg_name}"' not in line_str.lower():
                    continue
                ver_match = re.search(r'["\'][\^~]?([\d]+\.[\d]+\.[\d]+)', line_str)
                if ver_match:
                    version_str = ver_match.group(1)
                    if _is_version_vulnerable("==", version_str, vuln["safe_version"]):
                        issues.append({
                            "file": file_path,
                            "line": line_number + 1,
                            "code": line.strip(),
                            "severity": vuln["severity"],
                            "explanation": f"[{vuln['cve_id']}] {vuln['explanation']}",
                            "teach_back": "Supply chain attacks target outdated third-party libraries.",
                            "remediation": vuln["remediation"],
                            "fixed_code": f'"{pkg_name}": {vuln["fixed_code"]},  // SECURE: Upgraded',
                            "penalty": vuln["penalty"]
                        })

    return issues
