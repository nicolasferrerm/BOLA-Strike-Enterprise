"""
BOLA Strike Enterprise — Service Mesh Telemetry Interceptor (v10.0)
Simulates an eBPF/Envoy WASM filter that passively intercepts microservice
traffic within a Kubernetes mesh (e.g., Istio) to discover dynamic schemas
and inject BOLA payloads without relying on static OpenAPI definitions.
"""

import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ServiceMeshTelemetry:
    def __init__(self, cluster_name: str = "k8s-prod-mesh"):
        self.cluster_name = cluster_name
        self.intercepted_routes = {}

    def ingest_envoy_telemetry(self, raw_telemetry_data: List[Dict[str, Any]]):
        """
        Ingests simulated Envoy proxy access logs/telemetry streams.
        Expects a list of dicts with keys: 'upstream_cluster', 'path', 'method', 'status_code'
        """
        for entry in raw_telemetry_data:
            upstream = entry.get("upstream_cluster", "unknown_service")
            path = entry.get("path", "/")
            method = entry.get("method", "GET")

            # Simple route normalization (converting digits/UUIDs to parameters)
            norm_path = re.sub(
                r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                "/{uuid}",
                path,
            )
            norm_path = re.sub(r"/\d+(/|$)", "/{id}\\1", norm_path)
            # Additional normalization for random alphanumeric slugs (DoS prevention)
            norm_path = re.sub(r"/[a-zA-Z0-9_-]{16,}", "/{slug}", norm_path)

            route_key = f"{method} {upstream}:{norm_path}"

            if route_key not in self.intercepted_routes:
                # Bounded memory: LRU-style eviction (DoS prevention)
                if len(self.intercepted_routes) >= 5000:
                    self.intercepted_routes.pop(next(iter(self.intercepted_routes)))
                self.intercepted_routes[route_key] = {
                    "upstream": upstream,
                    "method": method,
                    "normalized_path": norm_path,
                    "raw_samples": set(),
                    "hit_count": 0,
                }

            if len(self.intercepted_routes[route_key]["raw_samples"]) < 5:
                self.intercepted_routes[route_key]["raw_samples"].add(path)
            self.intercepted_routes[route_key]["hit_count"] += 1

        logger.info(
            f"[ServiceMesh] Ingested telemetry. Discovered {len(self.intercepted_routes)} unique internal routes."
        )

    def generate_mesh_fuzzing_targets(self) -> List[Dict[str, Any]]:
        """Converts intercepted mesh routes into direct BOLA fuzzing targets."""
        targets = []
        for key, data in self.intercepted_routes.items():
            if "{uuid}" in data["normalized_path"] or "{id}" in data["normalized_path"]:
                targets.append(
                    {
                        "target_service": data["upstream"],
                        "method": data["method"],
                        "path_template": data["normalized_path"],
                        "samples": list(data["raw_samples"]),
                        "tags": ["mesh-intercept", "internal-api"],
                    }
                )
        return targets
