"""
BOLA Strike Enterprise — Multi-Step State Machine Fuzzer (v9.0)
Advanced module to fuzz complex API transaction workflows (e.g., Banking Transfers, Cart Checkouts).
Generates dynamic Directed Acyclic Graphs (DAG) to maintain state across requests.
"""
import copy
import uuid
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class StateMachineFuzzer:
    def __init__(self, workflow_name: str):
        self.workflow_name = workflow_name
        self.nodes = []  # Sequential API steps
        self.state_context = {}  # Extracted variables (e.g., tokens, transaction_ids)

    def add_step(self, method: str, path: str, payload_template: Dict = None, extract_vars: List[str] = None):
        """Add a step to the transaction DAG."""
        self.nodes.append({
            "method": method.upper(),
            "path": path,
            "payload_template": payload_template or {},
            "extract_vars": extract_vars or []
        })

    def _resolve_template(self, template: Any, context: Dict[str, Any]) -> Any:
        """Inject state context into the payload template."""
        if isinstance(template, dict):
            return {k: self._resolve_template(v, context) for k, v in template.items()}
        elif isinstance(template, list):
            return [self._resolve_template(i, context) for i in template]
        elif isinstance(template, str) and "$ctx." in template:
            # If the template is EXACTLY the variable, preserve its type (e.g. int/dict)
            if template.startswith("$ctx.") and len(template.split(".")) == 2 and template.count("$ctx.") == 1:
                var_name = template.replace("$ctx.", "")
                return context.get(var_name, template)
            
            import re
            def replace_var(match):
                var_name = match.group(1)
                return str(context.get(var_name, match.group(0)))
            return re.sub(r'\$ctx\.(\w+)', replace_var, template)
        return template

    def generate_fuzzing_scenarios(self, malicious_target_id: str) -> List[Dict[str, Any]]:
        """
        Generate execution plans where the final critical step is mutated 
        with BOLA payloads, but the prerequisite steps remain valid to pass validation.
        """
        if not self.nodes:
            return []

        scenarios = []
        # We assume the last node is the critical transaction commit (e.g., Transfer Funds)
        critical_node_idx = len(self.nodes) - 1
        
        # Attack 1: Swap Target ID in the critical payload
        attack_plan_1 = []
        for i, node in enumerate(self.nodes):
            step = copy.deepcopy(node)
            if i == critical_node_idx:
                # Mutate the payload to target another user's ID
                payload = self._resolve_template(step["payload_template"], {"target_account": malicious_target_id})
                step["is_attack_node"] = True
                step["attack_type"] = "BOLA_TRANSACTION_MANIPULATION"
            else:
                # Valid setup payload
                payload = self._resolve_template(step["payload_template"], {"target_account": "valid_user_account"})
                step["is_attack_node"] = False
            
            step["resolved_payload"] = payload
            attack_plan_1.append(step)
        
        scenarios.append({"scenario_id": str(uuid.uuid4()), "plan": attack_plan_1})
        
        # Attack 2: Combinatorial Out of order execution (State Bypass)
        if len(self.nodes) > 1:
            # Test direct final step
            attack_plan_2 = [copy.deepcopy(self.nodes[-1])]
            attack_plan_2[0]["is_attack_node"] = True
            attack_plan_2[0]["attack_type"] = "BFLA_STATE_BYPASS_DIRECT"
            attack_plan_2[0]["resolved_payload"] = self._resolve_template(self.nodes[-1]["payload_template"], {"target_account": malicious_target_id})
            scenarios.append({"scenario_id": str(uuid.uuid4()), "plan": attack_plan_2})
            
            # Test intermediate omissions
            if len(self.nodes) > 2:
                for skip_idx in range(1, critical_node_idx):
                    attack_plan_3 = []
                    for i, node in enumerate(self.nodes):
                        if i == skip_idx:
                            continue # Skip an intermediate step
                        step = copy.deepcopy(node)
                        if i == critical_node_idx:
                            step["is_attack_node"] = True
                            step["attack_type"] = f"BFLA_STATE_BYPASS_SKIP_STEP_{skip_idx}"
                            step["resolved_payload"] = self._resolve_template(step["payload_template"], {"target_account": malicious_target_id})
                        else:
                            step["is_attack_node"] = False
                            step["resolved_payload"] = self._resolve_template(step["payload_template"], {"target_account": "valid_user_account"})
                        attack_plan_3.append(step)
                    scenarios.append({"scenario_id": str(uuid.uuid4()), "plan": attack_plan_3})

        return scenarios

def build_banking_transfer_dag() -> StateMachineFuzzer:
    """Factory: Creates a standard banking transfer DAG for Canadian OSFI compliance testing."""
    fuzzer = StateMachineFuzzer("Banking_Fund_Transfer")
    # Step 1: Init Transfer (Creates transaction ID)
    fuzzer.add_step("POST", "/api/v1/transfer/init", {"amount": 500.00, "currency": "CAD"}, extract_vars=["transaction_id"])
    # Step 2: Validate Limits
    fuzzer.add_step("GET", "/api/v1/transfer/limits/$ctx.transaction_id")
    # Step 3: Commit Transfer (Vulnerable to BOLA on target_account)
    fuzzer.add_step("POST", "/api/v1/transfer/commit", {"transaction_id": "$ctx.transaction_id", "target_account": "$ctx.target_account"})
    return fuzzer
