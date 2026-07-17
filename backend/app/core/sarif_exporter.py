"""
BOLA Strike Enterprise — SARIF v2.1.0 Exporter (v7.0)
Addresses: F-012 (CI/CD workflow references --sarif flag that didn't exist)
Addresses: Audit v2.0 Task 2.1

Generates Static Analysis Results Interchange Format (SARIF) v2.1.0 output
compatible with:
- GitHub Advanced Security (Code Scanning)
- Azure DevOps
- SonarQube
- OWASP DefectDojo
"""

import json
import datetime
import re
from typing import List, Dict, Any
from app.version import __version__


def generate_sarif(
    results: List[Dict[str, Any]], target_url: str = ""
) -> Dict[str, Any]:
    """
    Generate a SARIF v2.1.0 compliant document from BOLA Strike findings.

    Args:
        results: List of finding dicts from the fuzzer engine.
        target_url: The API target URL that was scanned.

    Returns:
        A dict representing the full SARIF document.
    """
    rules = []
    sarif_results = []
    rule_ids_seen = set()

    for idx, res in enumerate(results):
        diagnosis = res.get("diagnosis", "")
        if "VULNERABLE" not in diagnosis and "WARNING" not in diagnosis:
            continue

        # Build a unique rule ID from the diagnosis category
        rule_id = _diagnosis_to_rule_id(diagnosis)
        severity_level = _severity_to_sarif_level(res.get("severity", "INFO"))

        # Register rule if not seen
        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            owasp = res.get("owasp", {}) or {}
            mitre = res.get("mitre_attack", {}) or {}

            help_text = f"**CWE:** {res.get('cwe', 'N/A')}\n"
            if owasp:
                help_text += (
                    f"**OWASP API:** {owasp.get('id', '')} — {owasp.get('name', '')}\n"
                )
            if mitre:
                help_text += f"**MITRE ATT&CK:** {mitre.get('tactic', '')} / {mitre.get('technique', '')} — {mitre.get('technique_name', '')}\n"

            rules.append(
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": diagnosis},
                    "fullDescription": {"text": res.get("remediation", diagnosis)},
                    "help": {"text": help_text, "markdown": help_text},
                    "defaultConfiguration": {"level": severity_level},
                    "properties": {
                        "tags": ["security", "api", "bola-strike"],
                        "precision": "high",
                        "security-severity": _severity_to_score(
                            res.get("severity", "INFO")
                        ),
                    },
                }
            )

        # Build the result entry
        message_text = (
            f"{diagnosis} on {res.get('method', '?')} {res.get('path', '?')}. "
            f"Baseline status: {res.get('base_status', '?')}, "
            f"Attacker status: {res.get('attack_status', '?')}. "
            f"Diff ratio: {res.get('diff_ratio', 0):.0%}. "
            f"Remediation: {res.get('remediation', 'N/A')}"
        )

        sarif_result = {
            "ruleId": rule_id,
            "ruleIndex": list(rule_ids_seen).index(rule_id),
            "level": severity_level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": res.get("path", "/unknown"),
                            "uriBaseId": "API_ROOT",
                        }
                    },
                    "logicalLocations": [
                        {
                            "fullyQualifiedName": f"{res.get('method', 'GET')} {res.get('path', '/')}",
                            "kind": "endpoint",
                        }
                    ],
                }
            ],
            "properties": {
                "severity": res.get("severity", "INFO"),
                "cwe": res.get("cwe", "N/A"),
                "diff_ratio": res.get("diff_ratio", 0),
                "timestamp": res.get(
                    "timestamp",
                    datetime.datetime.now(datetime.timezone.utc).isoformat(),
                ),
            },
        }

        # Attach PoC if available
        curl_poc = res.get("curl_poc", "")
        if curl_poc:
            sarif_result["attachments"] = [
                {
                    "description": {"text": "cURL Proof of Concept command"},
                    "artifactLocation": {"uri": f"poc_{idx}.sh"},
                }
            ]
            sarif_result["properties"]["curl_poc"] = curl_poc

        sarif_results.append(sarif_result)

    # Assemble the full SARIF document
    sarif_doc = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "BOLA Strike Enterprise",
                        "version": __version__,
                        "informationUri": "https://github.com/nicolasferrerm/bola_strike",
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "originalUriBaseIds": {
                    "API_ROOT": {
                        "uri": target_url or "http://unknown",
                        "description": {"text": "The base URL of the target API"},
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": datetime.datetime.now(
                            datetime.timezone.utc
                        ).isoformat(),
                    }
                ],
            }
        ],
    }

    return sarif_doc


def export_sarif(results: List[Dict[str, Any]], output_path: str, target_url: str = ""):
    """Generate and write SARIF to a file."""
    sarif = generate_sarif(results, target_url)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    return output_path


# --- Private Helpers ---


def _diagnosis_to_rule_id(diagnosis: str) -> str:
    """Convert a diagnosis string to a SARIF rule ID."""
    diag = diagnosis.upper()
    if "BFLA" in diag:
        return "BOLA_STRIKE_BFLA"
    elif "BOLA" in diag and "STATE" in diag:
        return "BOLA_STRIKE_BOLA_STATE_MUTATION"
    elif re.search(r"\b(MA|MASS)\b", diag):
        return "BOLA_STRIKE_MASS_ASSIGNMENT"
    elif "BOLA" in diag:
        return "BOLA_STRIKE_BOLA"
    elif "WARNING" in diag:
        return "BOLA_STRIKE_WARNING"
    return "BOLA_STRIKE_GENERIC"


def _severity_to_sarif_level(severity: str) -> str:
    """Map internal severity to SARIF level."""
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    return mapping.get((severity or "INFO").upper(), "note")


def _severity_to_score(severity: str) -> str:
    """Map severity to a SARIF security-severity score (0.0 - 10.0)."""
    mapping = {
        "CRITICAL": "9.5",
        "HIGH": "8.0",
        "MEDIUM": "5.5",
        "LOW": "3.0",
        "INFO": "1.0",
    }
    return mapping.get((severity or "INFO").upper(), "1.0")
