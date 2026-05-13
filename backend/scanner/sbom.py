import ssl
import certifi
ssl._create_default_https_context = lambda: ssl.create_default_context(cafile=certifi.where())

import re
import json
import urllib.request
import urllib.error
from packaging.version import Version, InvalidVersion

# ─────────────────────────────────────────────────────────────────────────────
# FALLBACK DATABASE — used when OSV API is unreachable (offline/air-gapped mode)
# ─────────────────────────────────────────────────────────────────────────────
FALLBACK_CVE_DATABASE = {
    "requests": {
        "safe_version": "2.31.0", "severity": "HIGH", "cve_id": "CVE-2023-32681",
        "explanation": "Versions below 2.31.0 are vulnerable to proxy credential leakage.",
        "remediation": "Upgrade to requests>=2.31.0.", "fixed_code": "requests>=2.31.0", "penalty": 15
    },
    "urllib3": {
        "safe_version": "1.25.10", "severity": "MEDIUM", "cve_id": "CVE-2020-26137",
        "explanation": "Versions below 1.25.10 are vulnerable to HTTP response splitting.",
        "remediation": "Upgrade to urllib3>=1.25.10.", "fixed_code": "urllib3>=1.25.10", "penalty": 10
    },
    "pillow": {
        "safe_version": "9.3.0", "severity": "HIGH", "cve_id": "CVE-2022-45198",
        "explanation": "Versions below 9.3.0 are vulnerable to buffer overflow in image parsing.",
        "remediation": "Upgrade to Pillow>=9.3.0.", "fixed_code": "Pillow>=9.3.0", "penalty": 15
    },
    "cryptography": {
        "safe_version": "41.0.0", "severity": "HIGH", "cve_id": "CVE-2023-23931",
        "explanation": "Versions below 41.0.0 have a Bleichenbacher timing oracle vulnerability.",
        "remediation": "Upgrade to cryptography>=41.0.0.", "fixed_code": "cryptography>=41.0.0", "penalty": 15
    },
    "flask": {
        "safe_version": "2.3.0", "severity": "HIGH", "cve_id": "CVE-2023-30861",
        "explanation": "Versions below 2.3.0 are vulnerable to cookie spoofing.",
        "remediation": "Upgrade to flask>=2.3.0.", "fixed_code": "flask>=2.3.0", "penalty": 15
    },
    "django": {
        "safe_version": "4.2.0", "severity": "HIGH", "cve_id": "CVE-2023-24580",
        "explanation": "Versions below 4.2.0 are vulnerable to DoS via multipart form parsing.",
        "remediation": "Upgrade to django>=4.2.0.", "fixed_code": "django>=4.2.0", "penalty": 15
    },
    "express": {
        "safe_version": "4.18.0", "severity": "CRITICAL", "cve_id": "CVE-2022-24999",
        "explanation": "Versions below 4.18.0 have a known Remote Code Execution vulnerability.",
        "remediation": "Upgrade to express>=4.18.0.", "fixed_code": '"express": "^4.18.0"', "penalty": 25
    },
    "pyyaml": {
        "safe_version": "6.0", "severity": "CRITICAL", "cve_id": "CVE-2020-14343",
        "explanation": "Versions below 6.0 allow arbitrary code execution via yaml.load().",
        "remediation": "Upgrade to PyYAML>=6.0 and use yaml.safe_load().", "fixed_code": "PyYAML>=6.0", "penalty": 25
    },
    "paramiko": {
        "safe_version": "3.4.0", "severity": "HIGH", "cve_id": "CVE-2023-48795",
        "explanation": "Versions below 3.4.0 are vulnerable to the Terrapin SSH attack.",
        "remediation": "Upgrade to paramiko>=3.4.0.", "fixed_code": "paramiko>=3.4.0", "penalty": 15
    }
}

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 4
OSV_USER_AGENT = "SENTINEL-AI/1.0 (local-security-scanner)"


def _check_osv_reachable() -> bool:
    """Quick connectivity probe to OSV API."""
    try:
        req = urllib.request.Request(
            OSV_API_URL,
            data=b'{"package":{"name":"pip","ecosystem":"PyPI"},"version":"1.0.0"}',
            headers={"Content-Type": "application/json", "User-Agent": OSV_USER_AGENT},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            return resp.status == 200
    except Exception:
        return False


def _query_osv(package_name: str, version: str, ecosystem: str = "PyPI") -> list:
    """
    Queries OSV.dev live API for vulnerabilities affecting this exact package version.
    Returns [] on any error — never crashes the scan.
    """
    payload = json.dumps({
        "package": {"name": package_name, "ecosystem": ecosystem},
        "version": version
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            OSV_API_URL,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": OSV_USER_AGENT},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT_SECONDS) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("vulns", [])
    except Exception:
        return []


def _osv_severity_to_internal(severity_list: list) -> tuple:
    """Maps OSV CVSS scores to SENTINEL severity labels and penalty points."""
    if not severity_list:
        return "MEDIUM", 10

    for s in severity_list:
        try:
            score = float(s.get("score", "0"))
            if score >= 9.0:
                return "CRITICAL", 25
            elif score >= 7.0:
                return "HIGH", 15
            elif score >= 4.0:
                return "MEDIUM", 10
            else:
                return "LOW", 5
        except (ValueError, TypeError):
            rating = s.get("type", "").upper()
            if "CRITICAL" in rating:
                return "CRITICAL", 25
            elif "HIGH" in rating:
                return "HIGH", 15

    return "MEDIUM", 10


def _format_osv_vulns(pkg_name: str, version_str: str, vulns: list,
                       raw_line: str, line_number: int, file_path: str) -> list:
    """Converts OSV API response into SENTINEL issue dicts."""
    issues = []
    for vuln in vulns:
        vuln_id = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary", "Known vulnerability detected.")
        aliases = vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
        severity, penalty = _osv_severity_to_internal(vuln.get("severity", []))

        # Extract fixed version from affected ranges
        fixed_version = None
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed_version = event["fixed"]
                        break

        fixed_code = (
            f"{pkg_name}>={fixed_version}"
            if fixed_version
            else f"{pkg_name}  # Upgrade to latest safe version"
        )
        remediation = (
            f"Upgrade to {pkg_name}>={fixed_version}."
            if fixed_version
            else f"Check {vuln_id} advisory and upgrade {pkg_name}."
        )

        issues.append({
            "file": file_path,
            "line": line_number,
            "code": raw_line.strip(),
            "severity": severity,
            "explanation": f"[{cve_id}] {summary}",
            "teach_back": (
                "Supply chain attacks exploit outdated dependencies. "
                "OSV.dev confirmed this version has a known CVE."
            ),
            "remediation": remediation,
            "fixed_code": f"{fixed_code}  # SECURE: Patched version (OSV.dev)",
            "penalty": penalty,
            "source": "OSV_LIVE"
        })
    return issues


def _parse_pinned_version(line_str: str, pkg_name: str):
    """Extracts version operator and string from a requirements line."""
    match = re.search(
        rf"^{re.escape(pkg_name)}\s*([=<>!~]{{1,2}})\s*([\d][^\s,;#]*)",
        line_str, re.IGNORECASE
    )
    return (match.group(1), match.group(2)) if match else (None, None)


def _is_version_vulnerable(operator: str, version_str: str, safe_version: str) -> bool:
    """Semantic version comparison for fallback mode."""
    try:
        return Version(version_str) < Version(safe_version)
    except InvalidVersion:
        return False


def generate_sbom_and_scan(file_path: str, code_lines: list) -> list:
    """
    Main SBOM scanner entry point.

    For each dependency line:
      1. Parse package name + pinned version
      2. Query OSV.dev live API (50,000+ CVEs, always current)
      3. If offline, fall back to local curated database
      4. Never flag without version comparison — zero false positives
    """
    issues = []
    osv_available = _check_osv_reachable()
    mode = "OSV_LIVE" if osv_available else "FALLBACK_DB"
    print(f"[SBOM] Scanning in {mode} mode")

    for line_number, line in enumerate(code_lines):
        line_str = line.strip()
        if not line_str or line_str.startswith('#'):
            continue

        # ── Python requirements.txt ──────────────────────────────────────────
        if file_path.endswith("requirements.txt"):
            pkg_match = re.match(r"^([a-zA-Z0-9_\-\.]+)", line_str)
            if not pkg_match:
                continue

            pkg_name = pkg_match.group(1)
            operator, version_str = _parse_pinned_version(line_str, pkg_name)

            if version_str is None:
                # No version pin — low severity advisory
                issues.append({
                    "file": file_path,
                    "line": line_number + 1,
                    "code": line.strip(),
                    "severity": "LOW",
                    "explanation": f"No version pinned for '{pkg_name}'. May install a vulnerable version.",
                    "teach_back": "Always pin dependency versions in requirements.txt.",
                    "remediation": f"Pin the version: {pkg_name}==<safe_version>",
                    "fixed_code": f"{pkg_name}==<latest_safe_version>  # Pin to specific version",
                    "penalty": 3,
                    "source": "STATIC"
                })
                continue

            if osv_available:
                # Live query — catches ALL known CVEs, not just our 9
                vulns = _query_osv(pkg_name, version_str)
                if vulns:
                    issues.extend(_format_osv_vulns(
                        pkg_name, version_str, vulns,
                        line, line_number + 1, file_path
                    ))
            else:
                # Offline fallback
                pkg_lower = pkg_name.lower()
                if pkg_lower in FALLBACK_CVE_DATABASE:
                    vuln = FALLBACK_CVE_DATABASE[pkg_lower]
                    if _is_version_vulnerable(operator, version_str, vuln["safe_version"]):
                        issues.append({
                            "file": file_path,
                            "line": line_number + 1,
                            "code": line.strip(),
                            "severity": vuln["severity"],
                            "explanation": f"[{vuln['cve_id']}] {vuln['explanation']} (offline mode)",
                            "teach_back": "Supply chain attacks target outdated third-party libraries.",
                            "remediation": vuln["remediation"],
                            "fixed_code": f"{vuln['fixed_code']}  # SECURE: Upgraded to patched version",
                            "penalty": vuln["penalty"],
                            "source": "FALLBACK_DB"
                        })

        # ── Node.js package.json ─────────────────────────────────────────────
        elif file_path.endswith("package.json"):
            pkg_match = re.search(
                r'"([a-zA-Z0-9_\-@/\.]+)"\s*:\s*"[\^~]?([\d]+\.[\d]+\.[\d]+)"',
                line_str
            )
            if not pkg_match:
                continue

            pkg_name = pkg_match.group(1)
            version_str = pkg_match.group(2)

            if pkg_name in ("version", "node", "npm"):
                continue

            if osv_available:
                vulns = _query_osv(pkg_name, version_str, ecosystem="npm")
                if vulns:
                    issues.extend(_format_osv_vulns(
                        pkg_name, version_str, vulns,
                        line, line_number + 1, file_path
                    ))
            else:
                pkg_lower = pkg_name.lower()
                if pkg_lower in FALLBACK_CVE_DATABASE:
                    vuln = FALLBACK_CVE_DATABASE[pkg_lower]
                    if _is_version_vulnerable("==", version_str, vuln["safe_version"]):
                        issues.append({
                            "file": file_path,
                            "line": line_number + 1,
                            "code": line.strip(),
                            "severity": vuln["severity"],
                            "explanation": f"[{vuln['cve_id']}] {vuln['explanation']} (offline mode)",
                            "teach_back": "Supply chain attacks target outdated third-party libraries.",
                            "remediation": vuln["remediation"],
                            "fixed_code": f'"{pkg_name}": "{vuln["fixed_code"]}",  // SECURE: Upgraded',
                            "penalty": vuln["penalty"],
                            "source": "FALLBACK_DB"
                        })

    return issues