from .static import scan_file_static
from .semantic import scan_file_semantic
from .sbom import generate_sbom_and_scan
from .privacy_guard import verify_air_gap
from .taint import run_taint_analysis


def calculate_score(issues: list) -> int:
    """
    Calculates a 0-100 integrity score by deducting penalty points per issue.
    Each issue carries its own penalty weight defined at detection time.
    """
    if not issues:
        return 100
    total_deduction = sum(i.get('penalty', 5) for i in issues)
    return max(5, 100 - total_deduction)


def _dedup_issues(raw_issues: list) -> list:
    """
    Deduplicates issues using file+line as the key.
    Priority order: DATA_FLOW_EXPLOIT > CRITICAL > HIGH > MEDIUM > LOW.
    Taint engine results always win over generic pattern matches on the same line.
    """
    SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    best = {}  # key -> best issue seen so far

    for issue in raw_issues:
        key = f"{issue.get('file')}:{issue.get('line')}"
        is_taint = issue.get("type") == "DATA_FLOW_EXPLOIT"
        rank = 99 if is_taint else SEVERITY_RANK.get(issue.get("severity", "LOW"), 0)

        if key not in best:
            best[key] = (rank, issue)
        else:
            existing_rank, _ = best[key]
            if rank > existing_rank:
                best[key] = (rank, issue)

    return [issue for _, issue in best.values()]


def analyze_project(extracted_files: dict, onnx_session) -> dict:
    raw_issues = []
    total_latency_ms = 0
    inference_count = 0
    is_project_air_gapped = True

    for file_path, code_lines in extracted_files.items():

        # ── Dependency files: SBOM scan only ────────────────────────────────
        if file_path.endswith(('requirements.txt', 'package.json')):
            raw_issues.extend(generate_sbom_and_scan(file_path, code_lines))
            continue

        # ── Source files: full analysis pipeline ────────────────────────────

        # 1. Static pattern scanner (secrets, SQL injection, debug mode)
        raw_issues.extend(scan_file_static(file_path, code_lines))

        # 2. Python-specific analysis
        if file_path.endswith('.py'):
            # 2a. Taint analysis (source-to-sink data flow tracking)
            taint_results = run_taint_analysis("\n".join(code_lines), filename=file_path)
            raw_issues.extend(taint_results)

            # 2b. Air-gap / network footprint check
            air_gap_check = verify_air_gap(file_path, code_lines)
            if not air_gap_check["is_air_gapped"]:
                is_project_air_gapped = False
                for violation in air_gap_check["violations"]:
                    raw_issues.append({
                        "file": file_path,
                        "line": violation["line"],
                        "code": f"import {violation['module']}",
                        "severity": "HIGH",
                        "explanation": (
                            f"Outbound network library '{violation['module']}' detected. "
                            "This creates an external data channel that may violate data residency requirements."
                        ),
                        "teach_back": (
                            "Each outbound network library is a potential data exfiltration vector. "
                            "In privacy-sensitive environments, all external connections must be audited."
                        ),
                        "remediation": (
                            "Audit all network calls. If required, isolate them behind a "
                            "dedicated secure proxy layer with egress filtering."
                        ),
                        "fixed_code": f"# AUDIT REQUIRED: import {violation['module']}  — verify data residency compliance",
                        "penalty": 10
                    })

            # 2c. Semantic AI scanner (CodeBERT ONNX — only if model loaded)
            if onnx_session:
                semantic_data = scan_file_semantic(file_path, code_lines, onnx_session)
                raw_issues.extend(semantic_data["issues"])
                if semantic_data["telemetries"]:
                    total_latency_ms += sum(semantic_data["telemetries"])
                    inference_count += len(semantic_data["telemetries"])

    # Deduplicate: keep the highest-priority finding per line
    all_issues = _dedup_issues(raw_issues)

    final_score = calculate_score(all_issues)
    avg_latency = (total_latency_ms / inference_count) if inference_count > 0 else 0

    return {
        "security_score": final_score,
        "is_air_gapped": is_project_air_gapped,
        "hardware_telemetry": {
            "total_onnx_calls": inference_count,
            "average_latency_ms": round(avg_latency, 2),
            "total_inference_time_ms": round(total_latency_ms, 2)
        },
        "issues": all_issues
    }
