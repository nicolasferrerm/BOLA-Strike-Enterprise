"""
BOLA Strike Enterprise — LLM-Driven Contextual Payload Generator (v10.0)
Leverages a local SLM/LLM (e.g., Ollama/Llama3 mock) to infer business context
from parameter names and generate highly relevant, semantic BOLA payloads
rather than relying on brute-force random strings.
"""

import json
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class LLMPayloadGenerator:
    def __init__(
        self,
        model_endpoint: str = "http://localhost:11434/api/generate",
        use_mock: bool = True,
    ):
        self.model_endpoint = model_endpoint
        self.use_mock = use_mock
        # Embedded fallback intelligence for when LLM is unreachable or mocked
        self._semantic_cache = {
            "invoice_id": ["INV-9999", "INV-0000", "TEST-INV-1"],
            "tenant_id": [
                "admin-tenant",
                "system-root",
                "00000000-0000-0000-0000-000000000000",
            ],
            "account_number": ["000000000", "999999999", "123456789"],
            "role": ["superadmin", "owner", "system"],
            "email": ["admin@target.local", "root@internal.corp", "sysadmin@bank.ca"],
        }

    def _query_local_llm(self, prompt: str) -> str:
        """Simulates querying a local Ollama instance for context inference."""
        if self.use_mock:
            # Simulate LLM reasoning
            if "invoice" in prompt.lower():
                return '{"suggested_payloads": ["INV-9999", "INV-0000"]}'
            elif "tenant" in prompt.lower():
                return '{"suggested_payloads": ["admin-tenant", "system-root"]}'
            return '{"suggested_payloads": ["admin", "root", "1"]}'

        # Real implementation would use requests.post to self.model_endpoint
        raise NotImplementedError(
            "Live LLM integration requires a running Ollama service."
        )

    def generate_contextual_payload(
        self, schema_parameters: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Takes a dict of parameter names and their types (e.g., {"tenant_id": "string", "amount": "number"})
        and uses the LLM to generate a malicious, context-aware payload object.
        """
        payload = {}
        for param_name, param_type in schema_parameters.items():
            # 1. Fast path: Semantic Cache Hit
            matched = False
            for key, payloads in self._semantic_cache.items():
                if key in param_name.lower():
                    payload[param_name] = payloads[0]  # Take the most aggressive one
                    matched = True
                    break

            # 2. Slow path: LLM Inference
            if not matched:
                import re

                # Prevent Prompt Injection by sanitizing external inputs
                safe_param = re.sub(r"[^a-zA-Z0-9_]", "", param_name)[:50]
                safe_type = re.sub(r"[^a-zA-Z0-9_]", "", param_type)[:20]
                prompt = f"Act as an expert penetration tester. Given an API parameter named '{safe_param}' of type '{safe_type}', suggest 2 malicious string values to test for IDOR/BOLA or privilege escalation. Return JSON."
                try:
                    llm_response = self._query_local_llm(prompt)
                    data = json.loads(llm_response)
                    payload[param_name] = data.get("suggested_payloads", ["1"])[0]
                except Exception:
                    logger.warning(
                        f"[LLM] Inference failed for {param_name}, falling back to generic payload."
                    )
                    payload[param_name] = "1" if param_type == "number" else "admin"

        return payload
