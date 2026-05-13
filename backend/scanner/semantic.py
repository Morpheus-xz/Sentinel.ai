import os
import ast
import time
import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer

MODEL_DIR = "models"
tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)

KNOWN_VULNERABILITIES = {
    "command_injection": {
        "code_pattern": "def execute_dynamic_code(user_payload):\n    return eval(user_payload)",
        "embedding": None,
        "severity": "CRITICAL",
        "explanation": "Dynamic execution of unsanitized variables detected.",
        "teach_back": "Evaluating dynamic variables allows attackers to pass malicious scripts that run directly on your server hardware.",
        "remediation": "Use safe parsers like ast.literal_eval() instead of eval().",
        "fixed_code": "import ast\n\n# Replaced eval() with a safe AST literal evaluation\nresult = ast.literal_eval(payload)",
        "penalty": 25
    }
}


def get_embedding(text: str, session: ort.InferenceSession):
    start_time = time.perf_counter()
    inputs = tokenizer(text, return_tensors="np", truncation=True, padding=True, max_length=512)
    ort_inputs = {
        session.get_inputs()[0].name: inputs["input_ids"],
        session.get_inputs()[1].name: inputs["attention_mask"]
    }
    ort_outputs = session.run(None, ort_inputs)
    embedding = np.mean(ort_outputs[0], axis=1)[0]
    latency_ms = (time.perf_counter() - start_time) * 1000
    return embedding, latency_ms


def initialize_semantic_scanner(session: ort.InferenceSession):
    if session is None: return
    for vuln_name, vuln_data in KNOWN_VULNERABILITIES.items():
        vuln_data["embedding"], _ = get_embedding(vuln_data["code_pattern"], session)


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


def is_dynamic_payload(node: ast.Call) -> bool:
    """
    ZERO ASSUMPTIONS: Checks if the argument passed to eval/exec is actually dynamic.
    If they are just evaluating a hardcoded string or number, it is safe.
    """
    if not node.args:
        return False
    arg = node.args[0]
    # If the argument is a hardcoded Constant (like a string or number), it's SAFE.
    if isinstance(arg, ast.Constant):
        return False
    # If it's a variable (Name), a dictionary lookup (Subscript), or function call, it's DANGEROUS.
    return True


def scan_file_semantic(file_path: str, code_lines: list, session: ort.InferenceSession) -> dict:
    issues = []
    telemetries = []
    if session is None or KNOWN_VULNERABILITIES["command_injection"]["embedding"] is None:
        return {"issues": issues, "telemetries": telemetries}

    code_content = "\n".join(code_lines)

    try:
        tree = ast.parse(code_content)
    except SyntaxError:
        return {"issues": issues, "telemetries": telemetries}

    # Walk the tree looking specifically for dangerous function calls
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']:

                # VERIFICATION: Is this actually a dangerous dynamic payload?
                if not is_dynamic_payload(node):
                    continue  # It's a safe, hardcoded evaluation. Skip it.

                # Extract the EXACT line of code
                exact_line_number = node.lineno
                exact_code = code_lines[exact_line_number - 1].strip()

                # Get the AI embedding for context matching
                block_embedding, latency_ms = get_embedding(exact_code, session)
                telemetries.append(latency_ms)

                for vuln_name, vuln_data in KNOWN_VULNERABILITIES.items():
                    sim_score = cosine_similarity(block_embedding, vuln_data["embedding"])

                    if sim_score > 0.85:  # We can lower the threshold because the AST verified the threat mathematically
                        issues.append({
                            "file": file_path,
                            "line": exact_line_number,  # EXACT LINE NUMBER
                            "code": exact_code,  # EXACT PROBLEM CODE
                            "severity": vuln_data["severity"],
                            "explanation": f"{vuln_data['explanation']} (AI Confidence: {sim_score:.2f})",
                            "teach_back": vuln_data["teach_back"],
                            "remediation": vuln_data["remediation"],
                            "fixed_code": exact_code.replace(node.func.id, "ast.literal_eval"),  # Precise auto-fix
                            "penalty": vuln_data["penalty"]
                        })

    return {"issues": issues, "telemetries": telemetries}