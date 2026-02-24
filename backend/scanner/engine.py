from .static import scan_file_static
from .semantic import scan_file_semantic
from .sbom import generate_sbom_and_scan
from .privacy_guard import verify_air_gap


def calculate_score(issues: list) -> int:
    if not issues: return 100
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 2}
    total_deduction = sum(weights.get(i.get('severity', 'MEDIUM'), 5) for i in issues)
    return max(5, 100 - total_deduction)


def analyze_project(extracted_files: dict, onnx_session) -> dict:
    all_issues = []
    total_latency_ms = 0
    inference_count = 0
    is_project_air_gapped = True

    for file_path, code_lines in extracted_files.items():
        if file_path.endswith(('requirements.txt', 'package.json')):
            all_issues.extend(generate_sbom_and_scan(file_path, code_lines))
            continue

        all_issues.extend(scan_file_static(file_path, code_lines))

        if file_path.endswith('.py'):
            # THE AIR-GAP CHECK FIX
            air_gap_check = verify_air_gap(file_path, code_lines)
            if not air_gap_check["is_air_gapped"]:
                is_project_air_gapped = False
                for violation in air_gap_check["violations"]:
                    all_issues.append({
                        "file": file_path,
                        "line": violation["line"],  # EXACT LINE NUMBER PASSED TO UI
                        "code": f"import {violation['module']}",
                        "severity": "HIGH",
                        "explanation": f"Outbound network library '{violation['module']}' detected in an environment requiring strict air-gapping.",
                        "teach_back": "To maintain zero data leakage, applications must not initiate unauthorized external network connections.",
                        "remediation": "Remove external API calls or isolate network functions to a dedicated secure proxy layer.",
                        "fixed_code": f"# Removed: import {violation['module']}  # SECURE: Air-Gap Maintained",
                        "penalty": 15
                    })

            if onnx_session:
                semantic_data = scan_file_semantic(file_path, code_lines, onnx_session)
                all_issues.extend(semantic_data["issues"])
                if semantic_data["telemetries"]:
                    total_latency_ms += sum(semantic_data["telemetries"])
                    inference_count += len(semantic_data["telemetries"])

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