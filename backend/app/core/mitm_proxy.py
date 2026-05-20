from mitmproxy import http
import json
import re
import os

class APIDiscoveryAddon:
    def __init__(self):
        self.discovered_endpoints = []
        self.output_file = "discovered_endpoints.json"
        
        # Cargar si ya existe
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r') as f:
                    self.discovered_endpoints = json.load(f)
            except (json.JSONDecodeError, IOError, ValueError) as e:
                print(f"[!] Warning: Could not load existing endpoints file: {e}")
                self.discovered_endpoints = []

    def response(self, flow: http.HTTPFlow):
        """
        Intercepta respuestas HTTP. Si es una API (ej. Content-Type application/json)
        y parece tener IDs en la URL, la guarda como un objetivo BOLA potencial.
        """
        # Filtrar solo JSON (APIs)
        content_type = flow.response.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            return

        method = flow.request.method
        url = flow.request.path
        
        # Evitar preflights y estáticos
        if method == "OPTIONS":
            return
            
        # Detectar patrones de UUID o IDs numéricos en la URL
        # Ejemplo: /api/users/1234 -> /api/users/TARGET_ID
        # Ejemplo: /api/orders/abc-123-xyz -> /api/orders/TARGET_ID
        
        fuzzed_url = re.sub(r'/[0-9]+(/|$)', '/TARGET_ID\\1', url)
        # Regex básico para UUIDs
        fuzzed_url = re.sub(r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(/|$)', '/TARGET_ID\\1', fuzzed_url)
        
        # Regex para Query Parameters (ej. ?id=123 o &user_id=abc)
        fuzzed_url = re.sub(r'([?&](?:id|uuid|user_id|account_id|target_id)=)[0-9a-zA-Z-]+', r'\g<1>TARGET_ID', fuzzed_url, flags=re.IGNORECASE)

        endpoint_def = {
            "path": fuzzed_url,
            "method": method,
            "original_path": url
        }
        
        # Evitar duplicados
        if not any(ep['path'] == fuzzed_url and ep['method'] == method for ep in self.discovered_endpoints):
            self.discovered_endpoints.append(endpoint_def)
            with open(self.output_file, 'w') as f:
                json.dump(self.discovered_endpoints, f, indent=4)
            print(f"[+] Endpoint BOLA potencial descubierto: {method} {fuzzed_url}")

addons = [
    APIDiscoveryAddon()
]
