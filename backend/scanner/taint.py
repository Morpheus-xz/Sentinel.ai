import ast


class TaintTracker(ast.NodeVisitor):
    def __init__(self, filename: str = "live_editor.py"):
        self.filename = filename
        self.tainted_state = {}
        self.exploits_found = []

        # Sources: Where untrusted data enters the application
        self.dangerous_sources = {
            'request.GET', 'request.POST', 'request.args',
            'request.form', 'request.json', 'request.data',
            'input', 'sys.argv', 'os.environ', 'os.environ.get', 'os.getenv'
        }

        # Sinks: Where untrusted data causes dangerous execution
        self.critical_sinks = {
            'eval', 'exec', 'os.system', 'os.popen',
            'subprocess.Popen', 'subprocess.run', 'subprocess.call',
            'compile', '__import__'
        }

    def visit_Assign(self, node):
        """Tracks when a variable is assigned untrusted data (Source tainting)."""
        try:
            if isinstance(node.value, ast.Subscript):
                source_name = ast.unparse(node.value.value)
                if source_name in self.dangerous_sources:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted_state[target.id] = {
                                "source_line": node.lineno,
                                "origin": source_name
                            }
            # Also track: user_data = input(...)
            elif isinstance(node.value, ast.Call):
                func_name = ast.unparse(node.value.func)
                if func_name in self.dangerous_sources:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted_state[target.id] = {
                                "source_line": node.lineno,
                                "origin": func_name
                            }
        except Exception:
            pass
        self.generic_visit(node)

    def visit_Call(self, node):
        """Checks if a tainted variable is passed into a dangerous function (Sink)."""
        try:
            func_name = ast.unparse(node.func)
            if func_name in self.critical_sinks:
                for arg in node.args:
                    # Direct tainted variable
                    if isinstance(arg, ast.Name) and arg.id in self.tainted_state:
                        taint_data = self.tainted_state[arg.id]
                        self.exploits_found.append({
                            "type": "DATA_FLOW_EXPLOIT",
                            "severity": "CRITICAL",
                            "file": self.filename,
                            "line": node.lineno,
                            "explanation": (
                                f"Exploit Path Verified: Untrusted data from "
                                f"'{taint_data['origin']}' (Line {taint_data['source_line']}) "
                                f"flows directly into '{func_name}()' without sanitization."
                            ),
                            "source_line": taint_data["source_line"],
                            "sink_line": node.lineno,
                            "tainted_variable": arg.id,
                            "code": f"{func_name}({arg.id})",
                            "teach_back": (
                                "Taint analysis confirms external user input flows directly into "
                                "an execution sink. An attacker can inject arbitrary code."
                            ),
                            "remediation": (
                                "Validate and sanitize input before use. "
                                "Prefer ast.literal_eval() over eval() for safe data parsing."
                            ),
                            "fixed_code": (
                                f"import ast\n"
                                f"# Sanitized: only allow safe literal values\n"
                                f"{arg.id} = ast.literal_eval({arg.id})\n"
                                f"{func_name}({arg.id})"
                            ),
                            "penalty": 30
                        })
        except Exception:
            pass
        self.generic_visit(node)


def run_taint_analysis(code_string: str, filename: str = "live_editor.py") -> list:
    """Executes taint tracking against a raw code string."""
    try:
        tree = ast.parse(code_string)
        tracker = TaintTracker(filename=filename)
        tracker.visit(tree)
        return tracker.exploits_found
    except SyntaxError:
        return []
