"""
BOLA Strike Enterprise — CVSS v4.0 Auto-Scoring Engine (v7.0)
Addresses: Audit v2.0 Task 3.3

Computes approximate CVSS v4.0 Base scores for API business logic vulnerabilities.
Factors: HTTP method (Attack Complexity), auth requirement (Privileges Required),
data sensitivity (Confidentiality/Integrity Impact).
"""
from typing import Dict, Any
import re

# CVSS v4.0 Base Metric approximations for API logic vulnerabilities
ATTACK_VECTOR = "Network"  # Always network for API attacks

METHOD_COMPLEXITY = {
    "GET": {"attack_complexity": "Low", "weight": 0.0},
    "POST": {"attack_complexity": "Low", "weight": 0.1},
    "PUT": {"attack_complexity": "Low", "weight": 0.15},
    "PATCH": {"attack_complexity": "Low", "weight": 0.1},
    "DELETE": {"attack_complexity": "Low", "weight": 0.2},
}

DIAGNOSIS_SCORES = {
    "BFLA": {"base": 9.8, "privileges_required": "Low", "ci": "High", "ii": "High", "ai": "None"},
    "BOLA_STATE": {"base": 9.1, "privileges_required": "Low", "ci": "High", "ii": "High", "ai": "None"},
    "BOLA": {"base": 8.6, "privileges_required": "Low", "ci": "High", "ii": "None", "ai": "None"},
    "MA": {"base": 7.5, "privileges_required": "Low", "ci": "Low", "ii": "High", "ai": "None"},
    "WARNING": {"base": 5.3, "privileges_required": "None", "ci": "Low", "ii": "None", "ai": "None"},
}


def _classify(diagnosis: str) -> str:
    d = diagnosis.upper()
    if "BFLA" in d:
        return "BFLA"
    if "STATE" in d and "BOLA" in d:
        return "BOLA_STATE"
    if re.search(r'\b(MA|MASS)\b', d):
        return "MA"
    if "WARNING" in d:
        return "WARNING"
    if "BOLA" in d:
        return "BOLA"
    return "WARNING"


def compute_cvss(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute an approximate CVSS v4.0 score for a finding.
    Returns a dict with score, vector string, and metric breakdown.
    """
    diagnosis = result.get("diagnosis", "")
    if "VULNERABLE" not in diagnosis and "WARNING" not in diagnosis:
        return {"score": 0.0, "rating": "None", "vector": "N/A", "metrics": {}}

    category = _classify(diagnosis)
    metrics = DIAGNOSIS_SCORES.get(category, DIAGNOSIS_SCORES["WARNING"])
    method = (result.get("method") or "GET").upper()
    method_data = METHOD_COMPLEXITY.get(method, METHOD_COMPLEXITY["GET"])

    # Adjust base score by method weight and diff ratio
    diff_ratio = result.get("diff_ratio", 0.5)
    adjusted = metrics["base"] + method_data["weight"]
    # Higher diff ratio = higher confidence = closer to base score
    adjusted = adjusted * (0.7 + 0.3 * diff_ratio)
    adjusted = min(10.0, max(0.1, round(adjusted, 1)))

    # Rating
    if adjusted >= 9.0:
        rating = "Critical"
    elif adjusted >= 7.0:
        rating = "High"
    elif adjusted >= 4.0:
        rating = "Medium"
    elif adjusted >= 0.1:
        rating = "Low"
    else:
        rating = "None"

    # Approximate CVSS v4.0 vector string
    vector = (
        f"CVSS:4.0/AV:N/AC:{method_data['attack_complexity'][0]}"
        f"/AT:N/PR:{metrics['privileges_required'][0]}/UI:N"
        f"/VC:{metrics['ci'][0]}/VI:{metrics['ii'][0]}/VA:{metrics['ai'][0]}"
        f"/SC:N/SI:N/SA:N"
    )

    return {
        "score": adjusted,
        "rating": rating,
        "vector": vector,
        "metrics": {
            "attack_vector": ATTACK_VECTOR,
            "attack_complexity": method_data["attack_complexity"],
            "privileges_required": metrics["privileges_required"],
            "confidentiality_impact": metrics["ci"],
            "integrity_impact": metrics["ii"],
            "availability_impact": metrics["ai"],
        }
    }


def enrich_with_cvss(results: list) -> list:
    """Add CVSS scoring to all findings in a results list."""
    for r in results:
        r["cvss"] = compute_cvss(r)
    return results
