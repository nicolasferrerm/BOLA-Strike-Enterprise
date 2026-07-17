import logging

logger = logging.getLogger(__name__)


class DefectDojoExporter:
    """
    Exports BOLA Strike findings to OWASP DefectDojo using the SARIF/JSON format.
    """

    def __init__(self, url, api_key, product_id):
        self.url = url
        self.api_key = api_key
        self.product_id = product_id

    def export(self, results):
        if not self.url or not self.api_key:
            return

        logger.info(f"Exporting {len(results)} results to DefectDojo...")

        # Simplified import structure for custom JSON format
        payload = {
            "product": self.product_id,
            "engagement": 1,  # Dummy engagement
            "scan_type": "Generic Findings Import",
            "findings": [],
        }

        for res in results:
            if "VULNERABLE" in res["diagnosis"]:
                payload["findings"].append(
                    {
                        "title": f"BOLA/BFLA in {res['method']} {res['path']}",
                        "severity": res["severity"].capitalize(),
                        "description": f"Endpoint {res['path']} is vulnerable. Base status: {res['base_status']}, Attack status: {res['attack_status']}. PoC: {res.get('curl_poc', '')}",
                        "cwe": int(res["cwe"].split(":")[0].replace("CWE-", ""))
                        if "CWE" in res["cwe"]
                        else 284,
                        "mitigation": res.get(
                            "remediation", "Implement strict RBAC/ABAC."
                        ),
                    }
                )

        if payload["findings"]:
            try:
                # In a real environment, this would hit the /api/v2/import-scan endpoint
                logger.info(
                    f"[DefectDojo] Would push {len(payload['findings'])} findings to {self.url}"
                )
            except Exception as e:
                logger.error(f"[DefectDojo] Failed to export: {e}")


class IntegrationsManager:
    @staticmethod
    def push_results(results, config):
        dojo_cfg = config.get("integrations", {}).get("defect_dojo", {})
        if dojo_cfg.get("enabled"):
            exporter = DefectDojoExporter(
                dojo_cfg.get("url"),
                dojo_cfg.get("api_key"),
                dojo_cfg.get("product_id", 1),
            )
            exporter.export(results)
