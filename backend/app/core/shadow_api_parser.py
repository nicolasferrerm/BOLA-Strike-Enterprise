"""
BOLA Strike Enterprise — Shadow API Discovery (v9.0)
Parses network traffic logs (e.g., PCAP exports, NGINX/Envoy JSON logs)
to discover undocumented endpoints and schema structures without OS kernel access.
"""

import re
import logging
from typing import List, Dict, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class ShadowAPIParser:
    def __init__(self):
        self.discovered_endpoints = defaultdict(
            lambda: {"methods": set(), "sample_paths": set()}
        )

    def ingest_nginx_log(self, log_path: str) -> int:
        """
        Parses NGINX access logs to find endpoints.
        Expected format includes method and path, e.g., "GET /api/v2/users/1234 HTTP/1.1"
        """
        count = 0
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                for line in f:
                    # Very basic regex to extract method and path from standard access log
                    match = re.search(
                        r'"(GET|POST|PUT|DELETE|PATCH)\s+(/.*?)\s+HTTP', line
                    )
                    if match:
                        method, path = match.groups()
                        # Normalize path by replacing UUIDs and Integers with {id}
                        normalized_path = re.sub(
                            r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                            "/{id}",
                            path,
                        )
                        normalized_path = re.sub(
                            r"/\d+(/|$)", "/{id}\\1", normalized_path
                        )
                        # Normalize arbitrary slugs (prevent OOM)
                        normalized_path = re.sub(
                            r"/[a-zA-Z0-9_-]{16,}", "/{slug}", normalized_path
                        )

                        self.discovered_endpoints[normalized_path]["methods"].add(
                            method
                        )
                        if (
                            len(
                                self.discovered_endpoints[normalized_path][
                                    "sample_paths"
                                ]
                            )
                            < 10
                        ):
                            self.discovered_endpoints[normalized_path][
                                "sample_paths"
                            ].add(path)
                        count += 1
            logger.info(
                f"[ShadowAPI] Ingested {count} log lines. Discovered {len(self.discovered_endpoints)} unique endpoints."
            )
        except Exception as e:
            logger.error(f"[ShadowAPI] Failed to ingest log {log_path}: {e}")
        return len(self.discovered_endpoints)

    def get_fuzzing_targets(self) -> List[Dict[str, Any]]:
        """Transforms discovered shadow endpoints into BOLA fuzzing targets."""
        targets = []
        for path, data in self.discovered_endpoints.items():
            if "{id}" in path:
                for method in data["methods"]:
                    targets.append(
                        {
                            "path": path,
                            "method": method,
                            "is_shadow_api": True,
                            "tags": ["shadow-api", "auto-discovered"],
                        }
                    )
        return targets
