"""
BOLA Strike Enterprise — SOAR Webhook Integration (v7.0)
Addresses: Audit v2.0 Task 3.2

Sends standardized webhook payloads to SOAR platforms for automated incident response:
- Cortex XSOAR
- Splunk Phantom / SOAR
- Microsoft Sentinel Playbooks
- Generic webhook (Slack, Teams, PagerDuty)
"""

import requests
import logging
import socket
import ipaddress
from urllib.parse import urlparse
import datetime
from typing import Dict, Any, List
from app.version import __version__

logger = logging.getLogger(__name__)


class SOARWebhook:
    """
    Dispatches findings to SOAR/alerting platforms via configurable webhooks.
    Supports filtering by severity threshold to prevent alert fatigue.
    """

    def __init__(
        self,
        webhook_url: str,
        min_severity: str = "HIGH",
        headers: Dict[str, str] = None,
        platform: str = "generic",
    ):
        self.webhook_url = webhook_url
        self.min_severity = min_severity
        self.custom_headers = headers or {}
        self.platform = platform
        self._severity_order = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0,
        }

    def _should_alert(self, severity: str) -> bool:
        return self._severity_order.get(severity, 0) >= self._severity_order.get(
            self.min_severity, 3
        )

    def _build_payload(self, result: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
        """Build a standardized SOAR-compatible payload."""
        owasp = result.get("owasp", {}) or {}
        mitre = result.get("mitre_attack", {}) or {}

        base_payload = {
            "source": "BOLA Strike Enterprise",
            "version": __version__,
            "scan_id": scan_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "finding": {
                "endpoint": f"{result.get('method', 'GET')} {result.get('path', '/')}",
                "diagnosis": result.get("diagnosis", "UNKNOWN"),
                "severity": result.get("severity", "INFO"),
                "cwe": result.get("cwe", "N/A"),
                "diff_ratio": result.get("diff_ratio", 0),
                "base_status": result.get("base_status"),
                "attack_status": result.get("attack_status"),
                "remediation": result.get("remediation", "N/A"),
                "curl_poc": "[REDACTED FOR WEBHOOK SECURITY]",
            },
            "context": {
                "owasp_api": owasp.get("id", "N/A"),
                "mitre_technique": mitre.get("technique", "N/A"),
                "mitre_tactic": mitre.get("tactic", "N/A"),
            },
            "recommended_action": self._recommend_action(result),
        }

        # Platform-specific formatting
        if self.platform == "slack":
            return self._format_slack(base_payload)
        elif self.platform == "teams":
            return self._format_teams(base_payload)

        return base_payload

    def _recommend_action(self, result: Dict[str, Any]) -> str:
        sev = result.get("severity", "INFO")
        if sev == "CRITICAL":
            return "IMMEDIATE: Revoke compromised tokens. Block attacker IP. Escalate to security lead."
        elif sev == "HIGH":
            return "URGENT: Investigate endpoint authorization logic. Create hotfix ticket."
        elif sev == "MEDIUM":
            return "REVIEW: Verify if the response is a false positive. Schedule remediation."
        return "MONITOR: Log for trend analysis."

    def _format_slack(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        f = payload["finding"]
        sev = f["severity"]
        emoji = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
        return {
            "text": f"{emoji} *BOLA Strike Alert — {sev}*",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *{f['diagnosis']}*\n`{f['endpoint']}`",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*CWE:* {f['cwe']}"},
                        {
                            "type": "mrkdwn",
                            "text": f"*OWASP:* {payload['context']['owasp_api']}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*MITRE:* {payload['context']['mitre_technique']}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Action:* {payload['recommended_action']}",
                        },
                    ],
                },
            ],
        }

    def _format_teams(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        f = payload["finding"]
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000" if f["severity"] == "CRITICAL" else "FFA500",
            "summary": f"BOLA Strike: {f['diagnosis']}",
            "sections": [
                {
                    "activityTitle": f"🛡️ BOLA Strike — {f['severity']}",
                    "facts": [
                        {"name": "Endpoint", "value": f["endpoint"]},
                        {"name": "Diagnosis", "value": f["diagnosis"]},
                        {"name": "CWE", "value": f["cwe"]},
                        {"name": "Action", "value": payload["recommended_action"]},
                    ],
                }
            ],
        }

    def dispatch(self, results: List[Dict[str, Any]], scan_id: str = "N/A") -> int:
        """Send alerts for all findings above the severity threshold. Returns count sent."""
        sent = 0
        for result in results:
            if not self._should_alert(result.get("severity", "INFO")):
                continue
            payload = self._build_payload(result, scan_id)
            try:
                parsed = urlparse(self.webhook_url)
                if parsed.scheme not in ("http", "https"):
                    logger.error(
                        f"[SOAR] Invalid webhook URL scheme (must be http/https): {self.webhook_url}"
                    )
                    continue
                try:
                    ip = socket.gethostbyname(parsed.hostname)
                    if (
                        ipaddress.ip_address(ip).is_private
                        or ipaddress.ip_address(ip).is_loopback
                    ):
                        logger.error(
                            f"[SOAR] SSRF Blocked: Webhook points to internal IP {ip}"
                        )
                        continue
                except Exception as e:
                    logger.error(f"[SOAR] Invalid webhook hostname: {e}")
                    continue
                headers = {"Content-Type": "application/json"}
                headers.update(self.custom_headers)
                resp = requests.post(
                    self.webhook_url, json=payload, headers=headers, timeout=10
                )
                if resp.status_code < 300:
                    sent += 1
                    logger.info(
                        f"[SOAR] Alert dispatched: {result.get('diagnosis')} → {self.platform}"
                    )
                else:
                    logger.warning(
                        f"[SOAR] Webhook returned {resp.status_code}: {resp.text[:200]}"
                    )
            except Exception as e:
                logger.error(f"[SOAR] Webhook failed: {e}")
        return sent


def dispatch_soar_alerts(results: List[Dict[str, Any]], config: dict) -> int:
    """Factory: Create webhook from config and dispatch."""
    soar_cfg = config.get("integrations", {}).get("soar", {})
    if not soar_cfg.get("enabled") or not soar_cfg.get("webhook_url"):
        return 0
    webhook = SOARWebhook(
        webhook_url=soar_cfg["webhook_url"],
        min_severity=soar_cfg.get("min_severity", "HIGH"),
        platform=soar_cfg.get("platform", "generic"),
        headers=soar_cfg.get("headers", {}),
    )
    return webhook.dispatch(results, scan_id=soar_cfg.get("scan_id", "N/A"))
