import ast


# Network libraries that indicate outbound connectivity
NETWORK_LIBS = {'requests', 'urllib', 'socket', 'http', 'ftplib', 'telnetlib', 'urllib3', 'httpx', 'aiohttp'}

# Libraries that are whitelisted because they are used internally by SENTINEL itself
# (only relevant when scanning SENTINEL's own code — keeps self-scan clean)
SENTINEL_INTERNAL_WHITELIST = set()


def verify_air_gap(file_path: str, code_lines: list) -> dict:
    """
    Scans Python AST to detect outbound network library imports.

    IMPORTANT DESIGN NOTE:
    This check is an ADVISORY flag, not a hard failure.
    The engine.py caller tags these as severity=HIGH (not CRITICAL)
    so they appear in results without dominating the score.

    This check only makes sense for projects that explicitly require
    air-gapped operation. For general projects it serves as a network
    footprint audit.
    """
    if not file_path.endswith('.py'):
        return {"is_air_gapped": True, "violations": []}

    code_content = "\n".join(code_lines)
    violations = []

    try:
        tree = ast.parse(code_content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    base_module = alias.name.split('.')[0].lower()
                    if base_module in NETWORK_LIBS and base_module not in SENTINEL_INTERNAL_WHITELIST:
                        violations.append({
                            "module": alias.name,
                            "line": node.lineno,
                            "kind": "direct_import"
                        })
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    base_module = node.module.split('.')[0].lower()
                    if base_module in NETWORK_LIBS and base_module not in SENTINEL_INTERNAL_WHITELIST:
                        violations.append({
                            "module": node.module,
                            "line": node.lineno,
                            "kind": "from_import"
                        })
    except SyntaxError:
        pass

    return {
        "is_air_gapped": len(violations) == 0,
        "violations": violations
    }
