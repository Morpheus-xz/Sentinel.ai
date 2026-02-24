import ast


class TaintTracker(ast.NodeVisitor):
    def __init__(self):
        # Maps variable names to their dangerous origin points
        self.tainted_state = {}
        self.exploits_found = []

        # Sources: Where untrusted data enters the application
        self.dangerous_sources = ['request.GET', 'request.POST', 'input', 'sys.argv', 'os.environ']

        # Sinks: Where untrusted data causes catastrophic execution
        self.critical_sinks = ['eval', 'exec', 'os.system', 'subprocess.Popen', 'subprocess.run']

    def visit_Assign(self, node):
        """Tracks when a variable is assigned untrusted data (The Source)."""
        try:
            # Handle cases like: user_payload = request.GET['q']
            if isinstance(node.value, ast.Subscript):
                source_name = ast.unparse(node.value.value)
                if source_name in self.dangerous_sources:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            # Mark the variable as tainted and record where it came from
                            self.tainted_state[target.id] = {
                                "source_line": node.lineno,
                                "origin": source_name
                            }
        except Exception:
            pass
        self.generic_visit(node)

    def visit_Call(self, node):
        """Checks if a tainted variable is passed into a dangerous function (The Sink)."""
        try:
            func_name = ast.unparse(node.func)
            if func_name in self.critical_sinks:
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id in self.tainted_state:
                        taint_data = self.tainted_state[arg.id]

                        # We have successfully tracked a full exploit path!
                        # We have successfully tracked a full exploit path!
                        self.exploits_found.append({
                            "type": "DATA_FLOW_EXPLOIT",
                            "severity": "CRITICAL",
                            "file": "live_editor.py",  # <-- ADD THIS
                            "line": node.lineno,  # <-- ADD THIS
                            "explanation": f"Exploit Path Verified: Untrusted data from '{taint_data['origin']}' (Line {taint_data['source_line']}) propagates directly into '{func_name}()'.",
                            "source_line": taint_data["source_line"],
                            "sink_line": node.lineno,
                            "tainted_variable": arg.id,
                            "code": f"{func_name}({arg.id})",
                            "teach_back": "Taint tracking confirms that external user input is flowing directly into an execution sink without prior sanitization.",
                            "remediation": "Implement strict type-checking and sanitization immediately after the data enters the application.",
                            "fixed_code": f"import ast\n# Sanitized flow\n{arg.id} = ast.literal_eval({arg.id})\n{func_name}({arg.id})"
                        })
        except Exception:
            pass
        self.generic_visit(node)


def run_taint_analysis(code_string: str) -> list:
    """Executes the taint tracking algorithm against a raw string of code."""
    try:
        tree = ast.parse(code_string)
        tracker = TaintTracker()
        tracker.visit(tree)
        return tracker.exploits_found
    except SyntaxError:
        return []