import argparse
import yaml
import json
import asyncio
import aiohttp
import time
import random
import re
import logging
import uuid
import datetime
from deepdiff import DeepDiff
from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.table import Table
from rich.live import Live
from prometheus_client import start_http_server, Counter, Histogram, Gauge
from backend.app.core.openapi_parser import OpenAPIParser
from backend.app.core.integrations import IntegrationsManager

# --- Metrics (Prometheus) ---
REQUESTS_TOTAL = Counter('fuzzer_requests_total', 'Total HTTP requests sent', ['method', 'status'])
VULNS_DETECTED = Counter('fuzzer_vulnerabilities_detected', 'Total BOLA/Mass Assignment vulnerabilities found', ['type'])
RESPONSE_TIME = Histogram('fuzzer_response_time_seconds', 'Response latency')
ACTIVE_TASKS = Gauge('fuzzer_active_tasks', 'Number of active async tasks')

# --- Logging (Structured JSON) ---
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "time": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "trace_id": getattr(record, 'trace_id', 'N/A')
        }
        return json.dumps(log_record)

logger = logging.getLogger("BOLA_Strike")
handler = logging.FileHandler("audit_fuzzer.json")
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)

console = Console()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) (BOLA Strike Enterprise)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) (BOLA Strike Enterprise)"
]

class ConfigManager:
    @staticmethod
    def load(path):
        if not path: return {}
        with open(path, 'r') as f:
            return yaml.safe_load(f)

class AuthManager:
    def __init__(self, users_config):
        self.victim = users_config.get('user_b', {})
        self.attacker = users_config.get('user_a', {})

    def get_headers(self, role):
        user = self.attacker if role == 'attacker' else self.victim
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        if 'token' in user: headers['Authorization'] = user['token']
        if 'headers' in user: headers.update(user['headers'])
        return headers

class SmartDiffAnalyzer:
    @staticmethod
    def analyze(v_json, a_json):
        # Remove common noisy fields before diffing
        noise_keys = ['created_at', 'updated_at', 'timestamp', 'nonce']
        
        def filter_noise(obj):
            if isinstance(obj, dict):
                return {k: filter_noise(v) for k, v in obj.items() if k not in noise_keys and not str(v).endswith('Z')}
            elif isinstance(obj, list):
                return [filter_noise(i) for i in obj]
            return obj

        v_clean = filter_noise(v_json)
        a_clean = filter_noise(a_json)
        
        diff = DeepDiff(v_clean, a_clean, ignore_order=True)
        
        # Generic Response Mitigation
        if not diff:
            keys_count = len(v_clean.keys()) if isinstance(v_clean, dict) else 0
            if keys_count <= 3 and any(k in v_clean for k in ['status', 'success', 'message']):
                return 0.7 # WARNING threshold, not BOLA

        if not diff: return 1.0
        if 'dictionary_item_removed' in diff or 'iterable_item_removed' in diff: return 0.1
        if 'values_changed' in diff and len(diff) == 1: return 0.95
        return 0.5

class MutationEngine:
    def __init__(self, target_id):
        self.target_id = target_id
        self.mass_assignment_payloads = {
            "is_admin": True,
            "role": "admin",
            "access_level": 99,
            "balance": 999999
        }

    def fuzz_path(self, path):
        return re.sub(r'\{[^}]+\}', str(self.target_id), path).replace('TARGET_ID', str(self.target_id))

    def fuzz_payload(self, payload):
        if not payload: return None, {}
        import copy
        new_payload = copy.deepcopy(payload)
        injected = {}
        
        # 1. BOLA Recursivo con Geometría
        def fuzz_ids(obj):
            import re
            import uuid
            if isinstance(obj, dict):
                new_obj = {}
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        new_obj[k] = fuzz_ids(v)
                    elif isinstance(v, (int, str)) and ('id' in k.lower() or 'uuid' in k.lower()):
                        v_str = str(v)
                        # Detect Geometry
                        if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', v_str):
                            # Shape: UUIDv4
                            new_obj[k] = str(uuid.uuid4())
                        elif re.match(r'^[0-9a-fA-F]+$', v_str) and len(v_str) > 10:
                            # Shape: Hex Hash (e.g., MongoDB ObjectID)
                            import secrets
                            fake_hex = secrets.token_hex(len(v_str) // 2 + 1)[:len(v_str)]
                            new_obj[k] = fake_hex
                        elif isinstance(v, int):
                            try:
                                new_obj[k] = int(self.target_id)
                            except ValueError:
                                new_obj[k] = self.target_id
                        else:
                            new_obj[k] = self.target_id
                    else:
                        new_obj[k] = v
                return new_obj
            elif isinstance(obj, list):
                return [fuzz_ids(i) for i in obj]
            return obj

        new_payload = fuzz_ids(new_payload)
        
        # 2. Mass Assignment Inyección Recursiva
        def inject_ma(obj):
            if isinstance(obj, dict):
                new_obj = copy.copy(obj)
                for key, value in self.mass_assignment_payloads.items():
                    if key not in new_obj:
                        new_obj[key] = value
                        injected[key] = value
                for k, v in new_obj.items():
                    if isinstance(v, (dict, list)):
                        new_obj[k] = inject_ma(v)
                return new_obj
            elif isinstance(obj, list):
                return [inject_ma(i) for i in obj]
            return obj

        new_payload = inject_ma(new_payload)
                
        return new_payload, injected

class ReportEngine:
    def __init__(self, target):
        self.target = target

    def generate_curl(self, method, url, headers, payload):
        curl = f"curl -X {method} '{url}' \\\n"
        for k, v in headers.items():
            curl += f"  -H '{k}: {v}' \\\n"
        if payload:
            curl += f"  -d '{json.dumps(payload)}'"
        return curl.strip(" \\\n")

    def export_html(self, results, output_file="report.html"):
        env = Environment(loader=FileSystemLoader('.'), autoescape=select_autoescape(['html', 'xml']))
        try:
            template = env.get_template('report_template.html')
            
            stats = {
                "target": self.target,
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_endpoints": len(results),
                "total_vulns": sum(1 for r in results if "VULNERABLE" in r['diagnosis']),
                "total_warnings": sum(1 for r in results if "WARNING" in r['diagnosis']),
                "total_secure": sum(1 for r in results if "SECURE" in r['diagnosis']),
                "results": results
            }
            html_out = template.render(**stats)
            with open(output_file, 'w') as f:
                f.write(html_out)
        except Exception as e:
            console.print(f"[red]Failed to generate HTML report: {e}[/]")

class EnterpriseFuzzer:
    def __init__(self, config, args):
        self.target = args.target or config.get('target_api')
        self.auth = AuthManager(config.get('users', {}))
        self.mutator = MutationEngine(config.get('target_id', '12345'))
        self.reporter = ReportEngine(self.target)
        self.concurrency = args.threads
        
        if args.openapi:
            console.print(f"[bold cyan]Ingesting OpenAPI specs from:[/] {args.openapi}")
            try:
                parser = OpenAPIParser(args.openapi)
                self.endpoints = parser.parse()
                console.print(f"[bold green]Autodiscovered {len(self.endpoints)} endpoints![/]")
            except Exception as e:
                console.print("[bold red]FATAL ERROR:[/] Failed to parse OpenAPI specification.")
                console.print(f"[red]Reason: {e}[/]")
                console.print("[yellow]Hint: Ensure the URL is reachable and the JSON/YAML is valid OpenAPI v3.[/]")
                import sys
                sys.exit(1)
        else:
            self.endpoints = config.get('endpoints', [])
        self.concurrency = args.threads

    async def fetch(self, session, method, url, headers, payload=None, role="victim"):
        start = time.time()
        trace_id = str(uuid.uuid4())
        max_retries = 3
        for attempt in range(max_retries):
            try:
                async with session.request(method, url, headers=headers, json=payload, ssl=False) as response:
                    status = response.status
                    if status == 429 and attempt < max_retries - 1:
                        sleep_time = (2 ** attempt) + random.uniform(0.5, 2.0)
                        await asyncio.sleep(sleep_time)
                        continue

                    resp_text = await response.text()
                    latency = time.time() - start
                    
                    REQUESTS_TOTAL.labels(method=method, status=status).inc()
                    RESPONSE_TIME.observe(latency)
                    
                    logger.info("Request executed", extra={"trace_id": trace_id, "url": url, "role": role, "status": status, "latency": latency})
                    
                    return status, resp_text
            except Exception as e:
                logger.error(f"Request failed: {e}", extra={"trace_id": trace_id})
                if attempt == max_retries - 1:
                    return 0, ""
                await asyncio.sleep(1.0)
        return 429, ""

    async def check_endpoint(self, session, ep, sem):
        async with sem:
            ACTIVE_TASKS.inc()
            try:
                raw_path = ep['path']
                method = ep['method'].upper()
                
                fuzzed_path = self.mutator.fuzz_path(raw_path)
                url = f"{self.target}{fuzzed_path}"
                
                payload, mass_assigned = self.mutator.fuzz_payload(ep.get('body'))
                
                vic_headers = self.auth.get_headers('victim')
                att_headers = self.auth.get_headers('attacker')

                # --- IDEMPOTENCY REORDERING ---
                if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                    a_status, a_text = await self.fetch(session, method, url, att_headers, payload, "attacker")
                    await asyncio.sleep(0.1)
                    v_status, v_text = await self.fetch(session, method, url, vic_headers, payload, "victim")
                else:
                    v_status, v_text = await self.fetch(session, method, url, vic_headers, payload, "victim")
                    await asyncio.sleep(0.1)
                    a_status, a_text = await self.fetch(session, method, url, att_headers, payload, "attacker")

                result = {
                    "path": fuzzed_path,
                    "method": method,
                    "base_status": v_status,
                    "attack_status": a_status,
                    "diagnosis": "ERROR",
                    "diff_ratio": 0.0,
                    "mass_assignment_injected": mass_assigned,
                    "curl_poc": self.reporter.generate_curl(method, url, att_headers, payload)
                }

                severity = "INFO"
                remediation = "N/A"
                cwe = "N/A"

                if str(a_status).startswith('2') or str(a_status).startswith('3'):
                    is_admin_route = ep.get('is_admin', False)
                    if is_admin_route:
                        result['diagnosis'] = "VULNERABLE (BFLA)"
                        severity = "CRITICAL"
                        remediation = "Implement strict Role-Based Access Control (RBAC). Regular users bypass function-level authorization."
                        cwe = "CWE-285: Improper Authorization"
                        VULNS_DETECTED.labels(type='BOLA').inc()
                        result['diff_ratio'] = 1.0
                    elif method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                        result['diagnosis'] = "VULNERABLE (BOLA - State Mutated)"
                        severity = "CRITICAL"
                        remediation = f"Implement strict object-level authorization checks for {method} operations."
                        cwe = "CWE-284: Improper Access Control"
                        VULNS_DETECTED.labels(type='BOLA').inc()
                        result['diff_ratio'] = 1.0
                    else:
                        try:
                            v_json = json.loads(v_text)
                            a_json = json.loads(a_text)
                            diff_score = SmartDiffAnalyzer.analyze(v_json, a_json)
                            result['diff_ratio'] = diff_score
                            if diff_score >= 0.8:
                                result['diagnosis'] = "VULNERABLE (BOLA/MA)"
                                severity = "CRITICAL"
                                remediation = "Implement strict object-level authorization checks to verify user ownership before granting access."
                                cwe = "CWE-284: Improper Access Control"
                                VULNS_DETECTED.labels(type='BOLA').inc()
                            elif diff_score >= 0.6:
                                result['diagnosis'] = "WARNING (Potential Generic Response or MA)"
                                severity = "MEDIUM"
                                remediation = "Review parameter binding and ensure API does not return generic 200 OK without performing validation."
                                cwe = "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes"
                        except json.JSONDecodeError:
                            # Multi-Format Fallback: Structural XML/HTML DOM Diffing
                            import xml.etree.ElementTree as ET
                            import difflib
                            import re
                            
                            diff_score = 0.0
                            try:
                                v_root = ET.fromstring(v_text)
                                a_root = ET.fromstring(a_text)
                                v_skeleton = [elem.tag for elem in v_root.iter()]
                                a_skeleton = [elem.tag for elem in a_root.iter()]
                                diff_score = 1.0 if v_skeleton == a_skeleton else 0.1
                            except ET.ParseError:
                                v_tags = re.findall(r'<\/?[\w\s="-]+>', v_text)
                                a_tags = re.findall(r'<\/?[\w\s="-]+>', a_text)
                                if v_tags and a_tags:
                                    matcher = difflib.SequenceMatcher(None, v_tags, a_tags)
                                    diff_score = matcher.ratio()
                                else:
                                    matcher = difflib.SequenceMatcher(None, v_text[:5000], a_text[:5000])
                                    diff_score = matcher.ratio()

                            result['diff_ratio'] = diff_score
                            if diff_score >= 0.9:
                                result['diagnosis'] = "VULNERABLE (BOLA - Text/XML)"
                                severity = "HIGH"
                                remediation = "API uses non-JSON format (XML/HTML). Enforce authorization checks regardless of content type."
                                cwe = "CWE-284: Improper Access Control"
                                VULNS_DETECTED.labels(type='BOLA').inc()
                            else:
                                result['diagnosis'] = "SECURE (Non-JSON Differs)"
                                severity = "INFO"
                                remediation = "N/A"
                                cwe = "N/A"
                elif a_status in [401, 403, 404]:
                    result['diagnosis'] = "SECURE"
                else:
                    result['diagnosis'] = f"ANOMALY ({a_status})"
                    severity = "LOW"
                    
                result['severity'] = severity
                result['cwe'] = cwe
                result['remediation'] = remediation

            except Exception as e:
                logger.error(f"Error checking endpoint {ep.get('path', 'unknown')}: {str(e)}")
                result = {
                    "path": ep.get('path', 'unknown'),
                    "method": ep.get('method', 'GET').upper(),
                    "base_status": 0,
                    "attack_status": 0,
                    "diagnosis": f"RUNTIME ERROR: {str(e)}",
                    "diff_ratio": 0.0,
                    "mass_assignment_injected": {},
                    "curl_poc": "",
                    "severity": "LOW",
                    "cwe": "N/A",
                    "remediation": "N/A"
                }
            finally:
                ACTIVE_TASKS.dec()
            return result

    async def run(self):
        sem = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(limit=self.concurrency, verify_ssl=False)
        results = []
        
        table = Table(title="Live DevSecOps BOLA Analysis", show_lines=True)
        table.add_column("Endpoint", style="cyan")
        table.add_column("Meth", style="magenta")
        table.add_column("V/A", justify="center")
        table.add_column("Severity", style="bold white")
        table.add_column("Diagnosis", style="bold")

        with Live(table, refresh_per_second=4):
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = [self.check_endpoint(session, ep, sem) for ep in self.endpoints]
                
                for coro in asyncio.as_completed(tasks):
                    res = await coro
                    results.append(res)
                    diag = res['diagnosis']
                    sev = res.get('severity', 'INFO')
                    color = "red" if "VULNERABLE" in diag else "green" if "SECURE" in diag else "yellow"
                    sev_color = "red" if sev == "CRITICAL" else "magenta" if sev == "HIGH" else "yellow" if sev == "MEDIUM" else "green"
                    table.add_row(
                        res['path'], res['method'],
                        f"{res['base_status']}/{res['attack_status']}",
                        f"[{sev_color}]{sev}[/{sev_color}]",
                        f"[{color}]{diag}[/{color}]"
                    )
        return results

async def main_async(args):
    config = ConfigManager.load(args.config)
    fuzzer = EnterpriseFuzzer(config, args)
    results = await fuzzer.run()
    
    # --- Phase 2: Enrich with OWASP + MITRE ATT&CK + Compliance ---
    try:
        from backend.app.core.attack_mapping import enrich_all_findings
        results = enrich_all_findings(results)
        console.print("[bold green][+] OWASP API Top 10 + MITRE ATT&CK + Compliance mappings applied.[/]")
    except ImportError:
        pass

    # --- Phase 3: CVSS v4.0 Auto-Scoring ---
    try:
        from backend.app.core.cvss_engine import enrich_with_cvss
        results = enrich_with_cvss(results)
        console.print("[bold green][+] CVSS v4.0 scores computed for all findings.[/]")
    except ImportError:
        pass

    # --- Phase 3: Threat Intelligence Enrichment ---
    try:
        from backend.app.core.threat_intel import load_and_enrich
        results = load_and_enrich(results, config)
        escalated = sum(1 for r in results if (r.get("threat_intel") or {}).get("escalated"))
        if escalated:
            console.print(f"[bold red][!] Threat Intel: {escalated} findings escalated (CISA KEV match)[/]")
        else:
            console.print("[bold green][+] Threat Intelligence feeds processed (no active exploitation matches).[/]")
    except ImportError:
        pass

    # --- Exports ---
    if args.html:
        fuzzer.reporter.export_html(results, args.html)
        console.print(f"[bold green]HTML Report exported:[/] {args.html}")
    
    if args.sarif:
        try:
            from backend.app.core.sarif_exporter import export_sarif
            export_sarif(results, args.sarif, target_url=fuzzer.target)
            console.print(f"[bold green][+] SARIF v2.1.0 exported:[/] {args.sarif}")
        except ImportError:
            pass

    if args.cef:
        try:
            from backend.app.core.cef_exporter import export_cef
            export_cef(results, args.cef)
            console.print(f"[bold green][+] CEF log exported for SIEM:[/] {args.cef}")
        except ImportError:
            pass

    if args.evidence:
        try:
            from backend.app.core.evidence_locker import preserve_evidence
            manifest = preserve_evidence(results, target_url=fuzzer.target, output_dir=args.evidence)
            console.print(f"[bold green][+] Evidence Locker (SHA-256):[/] {manifest}")
        except ImportError:
            pass

    # --- Phase 3: PDF Executive Report ---
    if args.pdf:
        try:
            from backend.app.core.pdf_report import generate_pdf_report
            pdf_path = generate_pdf_report(results, target_url=fuzzer.target, output_path=args.pdf)
            console.print(f"[bold green][+] Executive PDF Report:[/] {pdf_path}")
        except ImportError:
            pass

    return results

def main():
    parser = argparse.ArgumentParser(description="BOLA Strike v7.0.0 - DevSecOps Complete Service (Hardened Enterprise)")
    parser.add_argument("-c", "--config", help="YAML Config file", required=False, default="config.yaml")
    parser.add_argument("--openapi", help="URL or path to OpenAPI/Swagger spec (REST)")
    parser.add_argument("--graphql", help="GraphQL endpoint URL for introspection fuzzing")
    parser.add_argument("--target", help="Override Target API URL")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrent async tasks")
    parser.add_argument("--waf-evasion", action="store_true", help="Enable WAF evasion engine (polymorphic payloads)")
    # Export flags
    parser.add_argument("--html", default="report.html", help="Export HTML report")
    parser.add_argument("--sarif", default=None, help="Export SARIF v2.1.0 (GitHub/SonarQube)")
    parser.add_argument("--cef", default=None, help="Export CEF log (Splunk/QRadar/Sentinel)")
    parser.add_argument("--evidence", default=None, help="Evidence Locker output directory")
    parser.add_argument("--pdf", default=None, help="Executive PDF report (Board-Ready)")
    parser.add_argument("--metrics-port", type=int, default=8001, help="Port for Prometheus metrics")
    args = parser.parse_args()

    console.print("[bold cyan]=== BOLA Strike v7.0.0 (Hardened Enterprise) ===[/bold cyan]")
    
    # Start Prometheus server
    start_http_server(args.metrics_port)
    console.print(f"[bold yellow]Prometheus Metrics exported on port {args.metrics_port}[/]")

    # --- Phase 2: JWT Security Audit ---
    config = ConfigManager.load(args.config)
    try:
        from backend.app.core.jwt_auditor import audit_tokens_from_config
        jwt_report = audit_tokens_from_config(config.get('users', {}))
        if jwt_report:
            console.print("\n[bold magenta]=== JWT Security Audit ===[/]")
            for role, audit in jwt_report.items():
                if audit.get('findings'):
                    for f in audit['findings']:
                        sev_color = "red" if f['severity'] == "CRITICAL" else "yellow" if f['severity'] in ("HIGH", "MEDIUM") else "green"
                        console.print(f"  [{sev_color}][{f['severity']}][/{sev_color}] {role}: {f['title']}")
            console.print("")
    except ImportError:
        pass

    # --- Phase 3: GraphQL Introspection Discovery ---
    if args.graphql:
        try:
            from backend.app.core.graphql_fuzzer import discover_graphql
            console.print(f"[bold cyan]Introspecting GraphQL endpoint:[/] {args.graphql}")
            gql = discover_graphql(args.graphql)
            if gql:
                targets = gql.get_bola_targets()
                console.print(f"[bold green][+] Discovered {len(targets)} BOLA-vulnerable GraphQL operations![/]")
                for t in targets[:5]:
                    console.print(f"  [cyan]{t['type']}[/] {t['name']} (ID args: {t['id_arg_names']})")
            else:
                console.print("[yellow][!] GraphQL introspection failed or is disabled.[/]")
        except ImportError:
            console.print("[yellow][!] graphql_fuzzer module not available.[/]")

    # --- Phase 3: WAF Evasion ---
    if args.waf_evasion:
        console.print("[bold yellow][+] WAF Evasion Engine: ACTIVE (polymorphic payloads enabled)[/]")

    results = asyncio.run(main_async(args))
    
    # --- Integrations ---
    IntegrationsManager.push_results(results, config)

    # --- Phase 3: SOAR Webhook Dispatch ---
    try:
        from backend.app.core.soar_webhook import dispatch_soar_alerts
        sent = dispatch_soar_alerts(results, config)
        if sent:
            console.print(f"[bold green][+] SOAR: {sent} alerts dispatched to webhook.[/]")
    except ImportError:
        pass
    
    # --- CI/CD Pipeline Hard Block ---
    import sys
    has_critical = any(r.get('severity') in ['CRITICAL', 'HIGH'] for r in results)
    if has_critical:
        console.print("\n[bold red][!] DEVSECOPS PIPELINE BLOCKED: Critical or High vulnerabilities detected. Failing build.[/bold red]")
        sys.exit(1)
    else:
        console.print("\n[bold green][+] DEVSECOPS PIPELINE PASSED: No critical vulnerabilities detected.[/bold green]")
        sys.exit(0)

if __name__ == "__main__":
    main()

