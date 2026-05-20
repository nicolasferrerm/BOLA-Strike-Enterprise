import json
import time
import requests
import random
import re
from deepdiff import DeepDiff
from celery import Celery
from app.core.auth_manager import AuthManager
from app.core.openapi_parser import OpenAPIParser
from app.workers.payload_mutator import mutate_payload
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuración de Celery usando Redis como Broker y Backend
# F-005 FIX: Read from environment variables (set by docker-compose.yml)
import os
celery_app = Celery(
    "fuzzer_worker",
    broker=os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36 BOLA-Strike-Enterprise",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/16.6 Safari/605.1.15 BOLA-Strike-Enterprise"
]

def ast_json_diff(victim_content, attacker_content):
    try:
        v_json = json.loads(victim_content)
        a_json = json.loads(attacker_content)
    except json.JSONDecodeError:
        # Multi-Format Fallback: Structural XML/HTML DOM Diffing (O(N) Complexity)
        import xml.etree.ElementTree as ET
        import difflib
        import re
        
        v_str = victim_content.decode('utf-8') if isinstance(victim_content, bytes) else str(victim_content)
        a_str = attacker_content.decode('utf-8') if isinstance(attacker_content, bytes) else str(attacker_content)
        
        if not v_str and not a_str: return 1.0
        if not v_str or not a_str: return 0.0
        
        try:
            # Intentar Parseo Estructural Puro (XML)
            v_root = ET.fromstring(v_str)
            a_root = ET.fromstring(a_str)
            
            # Extraer el "esqueleto" (tags sin el texto dinámico como timestamps)
            v_skeleton = [elem.tag for elem in v_root.iter()]
            a_skeleton = [elem.tag for elem in a_root.iter()]
            
            if v_skeleton == a_skeleton:
                return 1.0 # Estructura idéntica, el BOLA falló
            else:
                return 0.1 # Estructura distinta, posible error 404/401 vs 200
        except ET.ParseError:
            # Fallback a HTML Skeleton extraction via Regex si falla el XML puro
            v_tags = re.findall(r'<\/?[\w\s="-]+>', v_str)
            a_tags = re.findall(r'<\/?[\w\s="-]+>', a_str)
            if v_tags and a_tags:
                 matcher = difflib.SequenceMatcher(None, v_tags, a_tags)
                 return matcher.ratio()
                 
            # Último recurso: Texto plano estricto
            matcher = difflib.SequenceMatcher(None, v_str[:5000], a_str[:5000]) # Cap en 5k chars para evitar colapso de CPU
            return matcher.ratio()

    diff = DeepDiff(v_json, a_json, ignore_order=True)
    
    # Generic Response Mitigation
    if not diff:
        keys_count = len(v_json.keys()) if isinstance(v_json, dict) else 0
        if keys_count <= 3 and any(k in v_json for k in ['status', 'success', 'message']):
            return 0.7 # WARNING threshold, not BOLA

    if not diff: return 1.0
    if 'dictionary_item_removed' in diff or 'iterable_item_removed' in diff: return 0.1
    if 'values_changed' in diff and len(diff) == 1: return 0.95
    return 0.5

def safe_request(method, url, **kwargs):
    """Ejecuta una petición con Exponential Backoff anti-WAF y resiliencia de red global"""
    import random
    max_retries = 3
    for attempt in range(max_retries):
        try:
            res = requests.request(method, url, **kwargs)
            if res.status_code == 429:
                sleep_time = (2 ** attempt) + random.uniform(0.5, 2.0)
                time.sleep(sleep_time)
                continue
            return res
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                # Mock a 503 response so the engine doesn't crash but logs the failure
                class DummyResponse:
                    status_code = 503
                    content = b'{}'
                return DummyResponse()
            sleep_time = (2 ** attempt) + random.uniform(0.5, 2.0)
            time.sleep(sleep_time)
    return None

@celery_app.task(bind=True)
def run_bola_fuzz(self, target_data: dict):
    """
    Tarea principal asíncrona que ejecuta la lógica de fuzzing BOLA.
    Ideal para ser procesada por múltiples workers.
    """
    target_url = target_data.get('target_url')
    target_id = target_data.get('target_id')
    endpoints = target_data.get('manual_endpoints', [])
    users_config = target_data.get('users_config', {})
    
    swagger_url = target_data.get('swagger_url')
    
    # Lógica de parseo de Swagger dinámica
    if swagger_url and not endpoints:
        try:
            parser = OpenAPIParser(swagger_url)
            endpoints = parser.parse()
        except Exception as e:
            results = [{"path": swagger_url, "method": "GET", "diagnosis": f"ERROR PARSING SWAGGER: {str(e)}", "severity": "CRITICAL"}]
            return {"status": "FAILED", "total_scanned": 0, "results": results}

    
    victim = users_config.get('user_b', {})
    attacker = users_config.get('user_a', {})
    
    auth_manager = AuthManager({"victim": victim, "attacker": attacker})
    
    results = []
    total_endpoints = len(endpoints)
    
    def process_endpoint(ep_tuple):
        i, ep = ep_tuple
        path = ep.get('path', '').replace('TARGET_ID', str(target_id))
        method = ep.get('method', 'GET').upper()
        url = f"{target_url}{path}"
        raw_body = ep.get('body', None)
        
        payload = mutate_payload(raw_body, target_id) if raw_body else None
        base_headers = {"User-Agent": random.choice(USER_AGENTS)}
        
        v_headers = auth_manager.get_headers('victim', base_headers)
        a_headers = auth_manager.get_headers('attacker', base_headers)
        
        try:
            if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                res_attacker = safe_request(method, url, headers=a_headers, json=payload, timeout=10, verify=False) if payload else safe_request(method, url, headers=a_headers, timeout=10, verify=False)
                time.sleep(0.1)
                res_victim = safe_request(method, url, headers=v_headers, json=payload, timeout=10, verify=False) if payload else safe_request(method, url, headers=v_headers, timeout=10, verify=False)
            else:
                res_victim = safe_request(method, url, headers=v_headers, json=payload, timeout=10, verify=False) if payload else safe_request(method, url, headers=v_headers, timeout=10, verify=False)
                time.sleep(0.1) 
                res_attacker = safe_request(method, url, headers=a_headers, json=payload, timeout=10, verify=False) if payload else safe_request(method, url, headers=a_headers, timeout=10, verify=False)

            diagnosis = "ERROR"
            diff_score = 0.0
            severity = "INFO"
            remediation = "N/A"
            cwe = "N/A"
            
            if str(res_attacker.status_code).startswith('2') or str(res_attacker.status_code).startswith('3'):
                is_admin_route = ep.get('is_admin', False)
                if is_admin_route:
                    diagnosis = "VULNERABLE (BFLA)"
                    severity = "CRITICAL"
                    remediation = "Implement strict Role-Based Access Control (RBAC). Regular users bypass function-level authorization."
                    cwe = "CWE-285: Improper Authorization"
                    diff_score = 1.0
                elif method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                    diagnosis = "VULNERABLE (BOLA - State Mutated)"
                    severity = "CRITICAL"
                    remediation = f"Implement strict object-level authorization checks for {method} operations."
                    cwe = "CWE-284: Improper Access Control"
                    diff_score = 1.0
                else:
                    diff_score = ast_json_diff(res_victim.content, res_attacker.content)
                    if diff_score >= 0.8:
                        diagnosis = "VULNERABLE (BOLA/MA)"
                        severity = "CRITICAL"
                        remediation = "Implement object-level authorization checks to verify user ownership before granting access to resources."
                        cwe = "CWE-284: Improper Access Control"
                    elif diff_score >= 0.6:
                        diagnosis = "WARNING (Potential Generic Response or MA)"
                        severity = "MEDIUM"
                        remediation = "Review parameter binding and ensure API does not return generic 200 OK without performing validation."
                        cwe = "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes"
                    else:
                        diagnosis = "SECURE (Behavior Differs)"
            elif res_attacker.status_code in [401, 403, 404]:
                diagnosis = "SECURE"
            else:
                diagnosis = f"ANOMALY ({res_attacker.status_code})"
                severity = "LOW"
                
            return {
                "path": path,
                "method": method,
                "base_status": res_victim.status_code,
                "attack_status": res_attacker.status_code,
                "diff_ratio": round(diff_score, 2),
                "diagnosis": diagnosis,
                "severity": severity,
                "cwe": cwe,
                "remediation": remediation,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        except Exception as e:
            return {"path": path, "method": method, "diagnosis": f"CONNECTION ERROR: {str(e)}"}

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(process_endpoint, item): item for item in enumerate(endpoints)}
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            if completed % 5 == 0 or completed == total_endpoints:
                self.update_state(state='PROGRESS', meta={'current': completed, 'total': total_endpoints})
            results.append(future.result())

    return {"status": "COMPLETED", "total_scanned": total_endpoints, "results": results}
