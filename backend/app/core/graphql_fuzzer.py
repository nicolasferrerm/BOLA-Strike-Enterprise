"""
BOLA Strike Enterprise — GraphQL Introspection Fuzzer (v7.0)
Addresses: Audit v2.0 Task 3.5

Discovers and fuzzes GraphQL APIs for authorization vulnerabilities:
- Introspection query to auto-discover schema
- Query depth attacks
- Mutation authorization bypass (BOLA on GraphQL mutations)
- Field-level authorization testing
"""

import requests
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""


class GraphQLFuzzer:
    """
    Discovers GraphQL schemas via introspection and generates BOLA fuzzing targets.
    """

    def __init__(self, endpoint: str, headers: Dict[str, str] = None):
        self.endpoint = endpoint
        self.headers = headers or {"Content-Type": "application/json"}
        self.schema = None
        self.queries = []
        self.mutations = []

    def introspect(self) -> bool:
        """Run introspection query to discover the schema."""
        try:
            resp = requests.post(
                self.endpoint,
                json={"query": INTROSPECTION_QUERY},
                headers=self.headers,
                timeout=15,
                verify=True,
            )
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data["data"]:
                    self.schema = data["data"]["__schema"]
                    self._extract_operations()
                    logger.info(
                        f"[GraphQL] Introspection succeeded: {len(self.queries)} queries, {len(self.mutations)} mutations"
                    )
                    return True
                elif "errors" in data:
                    logger.warning(
                        f"[GraphQL] Introspection disabled or restricted: {data['errors'][0].get('message', '')}"
                    )
                    return False
            else:
                logger.warning(
                    f"[GraphQL] Introspection returned HTTP {resp.status_code}"
                )
                return False
        except Exception as e:
            logger.error(f"[GraphQL] Introspection failed: {e}")
            return False

    def _extract_operations(self):
        """Extract queries and mutations from the introspection schema."""
        if not self.schema:
            return

        type_map = {
            t["name"]: t for t in self.schema.get("types", []) if t.get("fields")
        }
        query_type_name = (self.schema.get("queryType") or {}).get("name", "Query")
        mutation_type_name = (self.schema.get("mutationType") or {}).get(
            "name", "Mutation"
        )

        if query_type_name in type_map:
            for field in type_map[query_type_name].get("fields", []):
                self.queries.append(self._build_operation("query", field))

        if mutation_type_name in type_map:
            for field in type_map[mutation_type_name].get("fields", []):
                self.mutations.append(self._build_operation("mutation", field))

    def _build_operation(self, op_type: str, field: Dict) -> Dict[str, Any]:
        """Build a fuzzing target from a GraphQL field."""
        args = field.get("args", [])
        # Detect ID-like arguments (BOLA targets)
        id_args = [a for a in args if "id" in a["name"].lower()]
        has_id = len(id_args) > 0

        # Build a template query/mutation
        arg_str = ""
        if args:
            arg_parts = []
            for a in args:
                type_name = self._resolve_type_name(a.get("type", {}))
                if "id" in a["name"].lower():
                    arg_parts.append(f'{a["name"]}: "TARGET_ID"')
                elif type_name in ("String", "string"):
                    arg_parts.append(f'{a["name"]}: "test"')
                elif type_name in ("Int", "Float", "int", "float"):
                    arg_parts.append(f"{a['name']}: 1")
                elif type_name in ("Boolean", "boolean"):
                    arg_parts.append(f"{a['name']}: true")
                else:
                    arg_parts.append(f'{a["name"]}: "test"')
            arg_str = f"({', '.join(arg_parts)})"

        return_type = self._resolve_type_name(field.get("type", {}))
        template = f"{op_type} {{ {field['name']}{arg_str} {{ id __typename }} }}"

        return {
            "name": field["name"],
            "type": op_type,
            "template": template,
            "has_id_arg": has_id,
            "id_arg_names": [a["name"] for a in id_args],
            "return_type": return_type,
            "is_bola_target": has_id,
        }

    def _resolve_type_name(self, type_obj: Dict) -> str:
        if type_obj.get("name"):
            return type_obj["name"]
        if type_obj.get("ofType"):
            return self._resolve_type_name(type_obj["ofType"])
        return "Unknown"

    def get_bola_targets(self) -> List[Dict[str, Any]]:
        """Return only operations that accept ID arguments (BOLA attack surface)."""
        targets = []
        for op in self.queries + self.mutations:
            if op["is_bola_target"]:
                targets.append(op)
        return targets

    def generate_endpoints_for_fuzzer(
        self, target_id: str = "TARGET_ID"
    ) -> List[Dict[str, Any]]:
        """Convert discovered operations into the standard endpoint format for the main fuzzer."""
        endpoints = []
        for op in self.get_bola_targets():
            query = op["template"].replace("TARGET_ID", str(target_id))
            endpoints.append(
                {
                    "path": self.endpoint,
                    "method": "POST",
                    "body": {"query": query},
                    "is_admin": False,
                    "tags": [f"graphql-{op['type']}", op["name"]],
                    "graphql_operation": op["name"],
                }
            )
        return endpoints


def discover_graphql(
    endpoint: str, headers: Dict[str, str] = None
) -> Optional[GraphQLFuzzer]:
    """Factory: Attempt GraphQL introspection and return a fuzzer if successful."""
    fuzzer = GraphQLFuzzer(endpoint, headers)
    if fuzzer.introspect():
        return fuzzer
    return None
