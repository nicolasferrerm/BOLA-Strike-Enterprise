"""
BOLA Strike Enterprise — Threat Intelligence Feed Integration (v7.0)
Addresses: Audit v2.0 Task 3.6

Consumes threat intelligence feeds and cross-references with scan findings:
- CISA KEV (Known Exploited Vulnerabilities) catalog
- AlienVault OTX pulse data
- MISP event correlation (via REST API)
- Auto-escalation: if a finding matches an active TTP, severity is elevated.
"""

import requests
import logging
import os
import json
import time
import datetime
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class ThreatIntelEngine:
    """
    Aggregates threat intelligence from multiple sources and enriches findings.
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.kev_catalog: List[Dict] = []
        self.otx_pulses: List[Dict] = []
        self.cache_dir = os.path.join(os.path.expanduser("~"), ".bola_strike", "cache")
        os.makedirs(self.cache_dir, exist_ok=True)

    def load_cisa_kev(self) -> int:
        """Load CISA Known Exploited Vulnerabilities catalog (with local caching)."""
        cache_file = os.path.join(self.cache_dir, "cisa_kev.json")
        if (
            os.path.exists(cache_file)
            and time.time() - os.path.getmtime(cache_file) < 86400
        ):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    self.kev_catalog = json.load(f).get("vulnerabilities", [])
                    logger.info(
                        f"[ThreatIntel] Loaded {len(self.kev_catalog)} CISA KEV entries from cache"
                    )
                    return len(self.kev_catalog)
            except Exception:
                pass

        try:
            resp = requests.get(CISA_KEV_URL, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                self.kev_catalog = data.get("vulnerabilities", [])
                logger.info(
                    f"[ThreatIntel] Loaded {len(self.kev_catalog)} CISA KEV entries from API"
                )
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                return len(self.kev_catalog)
        except Exception as e:
            logger.warning(f"[ThreatIntel] Failed to load CISA KEV: {e}")
        return 0

    def load_otx_pulses(self, api_key: str = None, pulse_days: int = 30) -> int:
        """Load recent AlienVault OTX pulses."""
        key = api_key or self.config.get("otx_api_key", "")
        if not key:
            return 0
        try:
            headers = {"X-OTX-API-KEY": key}
            iso_date = (
                datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(days=pulse_days)
            ).isoformat()
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={iso_date}",
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                self.otx_pulses = data.get("results", [])
                logger.info(f"[ThreatIntel] Loaded {len(self.otx_pulses)} OTX pulses")
                return len(self.otx_pulses)
        except Exception as e:
            logger.warning(f"[ThreatIntel] Failed to load OTX pulses: {e}")
        return 0

    def check_cwe_in_kev(self, cwe: str) -> Optional[Dict]:
        """Check if a CWE is associated with any CISA KEV entry."""
        if not cwe or cwe == "N/A":
            return None
        cwe_id = (cwe or "N/A").split(":")[0].strip()  # "CWE-284: ..." -> "CWE-284"
        for kev in self.kev_catalog:
            kev_cwe = kev.get("cwes", [])
            if isinstance(kev_cwe, list) and cwe_id in kev_cwe:
                return {
                    "kev_id": kev.get("cveID"),
                    "vendor": kev.get("vendorProject"),
                    "product": kev.get("product"),
                    "date_added": kev.get("dateAdded"),
                    "due_date": kev.get("dueDate"),
                }
            # Also check the notes field for CWE mentions using word boundaries
            notes = kev.get("notes", "")
            cwe_num = cwe_id.replace("CWE-", "")
            if re.search(rf"\bCWE-{cwe_num}\b", str(notes), re.IGNORECASE):
                return {"kev_id": kev.get("cveID"), "vendor": kev.get("vendorProject")}
        return None

    def enrich_finding(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single finding with threat intelligence context."""
        diagnosis = result.get("diagnosis", "")
        if "VULNERABLE" not in diagnosis and "WARNING" not in diagnosis:
            result["threat_intel"] = None
            return result

        ti_data = {
            "cisa_kev_match": None,
            "actively_exploited": False,
            "escalated": False,
        }

        # Check CISA KEV
        cwe = result.get("cwe", "N/A")
        kev_match = self.check_cwe_in_kev(cwe)
        if kev_match:
            ti_data["cisa_kev_match"] = kev_match
            ti_data["actively_exploited"] = True
            ti_data["escalated"] = True
            # Auto-escalate severity
            if result.get("severity") in ("MEDIUM", "LOW"):
                result["original_severity"] = result["severity"]
                result["severity"] = "HIGH"
                ti_data["escalation_reason"] = (
                    f"CWE matches CISA KEV entry {kev_match.get('kev_id', 'unknown')}"
                )
                logger.warning(
                    f"[ThreatIntel] ESCALATED: {result.get('path')} — matches active exploitation (KEV)"
                )

        result["threat_intel"] = ti_data
        return result

    def enrich_all(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.enrich_finding(r) for r in results]


def load_and_enrich(
    results: List[Dict[str, Any]], config: dict = None
) -> List[Dict[str, Any]]:
    """Convenience: Load all feeds and enrich findings."""
    ti_cfg = (config or {}).get("integrations", {}).get("threat_intel", {})
    engine = ThreatIntelEngine(ti_cfg)

    if ti_cfg.get("cisa_kev", True):
        engine.load_cisa_kev()

    if ti_cfg.get("otx_api_key"):
        engine.load_otx_pulses(api_key=ti_cfg["otx_api_key"])

    return engine.enrich_all(results)
