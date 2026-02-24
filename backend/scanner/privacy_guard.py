import ast


def verify_air_gap(file_path: str, code_lines: list) -> dict:
    """Scans the AST to ensure no outbound network libraries are imported."""
    if not file_path.endswith('.py'):
        return {"is_air_gapped": True, "violations": []}

    code_content = "\n".join(code_lines)
    network_libs = {'requests', 'urllib', 'socket', 'http', 'ftplib', 'telnetlib', 'urllib3'}
    violations = []

    try:
        tree = ast.parse(code_content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    base_module = alias.name.split('.')[0].lower()
                    if base_module in network_libs:
                        # Grab the EXACT line number of the import
                        violations.append({"module": alias.name, "line": node.lineno})
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    base_module = node.module.split('.')[0].lower()
                    if base_module in network_libs:
                        # Grab the EXACT line number of the import
                        violations.append({"module": node.module, "line": node.lineno})
    except SyntaxError:
        pass

    return {
        "is_air_gapped": len(violations) == 0,
        "violations": violations
    }