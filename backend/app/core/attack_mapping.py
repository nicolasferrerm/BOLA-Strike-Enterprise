"""
BOLA Strike Enterprise — MITRE ATT&CK + OWASP API Top 10 + Compliance Mapping (v7.0)
Addresses: Audit v2.0 Tasks 2.6 and 2.7

Provides a centralized taxonomy engine that enriches every finding with:
- OWASP API Security Top 10 (2023) reference
- MITRE ATT&CK Tactic + Technique ID
- Regulatory compliance mapping (PCI-DSS, SOC2, GDPR, ISO 27001)
"""

from typing import Dict, Any, Optional
import re

# --- OWASP API Security Top 10 (2023) ---
OWASP_API_MAP = {
    "BOLA": {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        "description": "APIs expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues."
    },
    "BFLA": {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
        "description": "Complex access control policies with different hierarchies, groups, and roles can lead to authorization flaws."
    },
    "MA": {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization (BOPLA)",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        "description": "Lack of or improper authorization validation at object property level leads to information exposure or manipulation."
    },
    "AUTH": {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        "description": "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens."
    },
}

# --- MITRE ATT&CK for Enterprise ---
MITRE_ATTACK_MAP = {
    "BOLA": {
        "tactic": "TA0009 - Collection",
        "technique": "T1530",
        "technique_name": "Data from Cloud Storage Object",
        "description": "Adversary accesses data objects belonging to other users by manipulating object references.",
        "url": "https://attack.mitre.org/techniques/T1530/"
    },
    "BFLA": {
        "tactic": "TA0004 - Privilege Escalation",
        "technique": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "description": "Adversary bypasses function-level access controls to perform administrative actions.",
        "url": "https://attack.mitre.org/techniques/T1548/"
    },
    "MA": {
        "tactic": "TA0005 - Defense Evasion",
        "technique": "T1036",
        "technique_name": "Masquerading",
        "description": "Adversary manipulates object properties (role, permissions) to escalate privileges via mass assignment.",
        "url": "https://attack.mitre.org/techniques/T1036/"
    },
    "STATE_MUTATION": {
        "tactic": "TA0040 - Impact",
        "technique": "T1565.001",
        "technique_name": "Stored Data Manipulation",
        "description": "Adversary mutates state of another user's resource via unauthorized write operations.",
        "url": "https://attack.mitre.org/techniques/T1565/001/"
    },
}

# --- Regulatory Compliance Mapping ---
COMPLIANCE_MAP = {
    "BOLA": {
        "PCI-DSS": "Req 7.1 — Restrict access to system components and cardholder data to only those individuals whose job requires such access.",
        "SOC2": "CC6.1 — Logical and Physical Access Controls",
        "GDPR": "Article 25 — Data protection by design and by default; Article 32 — Security of processing",
        "ISO_27001": "A.9.4.1 — Information access restriction",
        "NIST_CSF": "PR.AC-4 — Access permissions and authorizations are managed",
        "HIPAA": "164.312(a)(1) — Access Control",
        "FedRAMP": "AC-3 — Access Enforcement",
        "CIS_Controls": "14.6 — Protect Information through Access Control Lists",
    },
    "BFLA": {
        "PCI-DSS": "Req 7.2 — Establish an access control system for systems components that restricts access based on a user's need to know.",
        "SOC2": "CC6.3 — Role-Based Access and Least Privilege",
        "GDPR": "Article 32 — Security of processing",
        "ISO_27001": "A.9.2.3 — Management of privileged access rights",
        "NIST_CSF": "PR.AC-4 — Access permissions and authorizations are managed",
        "HIPAA": "164.312(a)(1) — Access Control",
        "FedRAMP": "AC-6 — Least Privilege",
        "CIS_Controls": "5.4 — Restrict Administrator Privileges to Dedicated Administrator Accounts",
    },
    "MA": {
        "PCI-DSS": "Req 6.5.8 — Improper access control (such as insecure direct object references, failure to restrict URL access).",
        "SOC2": "CC6.1 — Logical and Physical Access Controls",
        "GDPR": "Article 5(1)(f) — Integrity and confidentiality",
        "ISO_27001": "A.14.2.5 — Secure system engineering principles",
        "NIST_CSF": "PR.DS-6 — Integrity checking mechanisms are used",
        "HIPAA": "164.312(c)(1) — Integrity",
        "FedRAMP": "SI-10 — Information Input Validation",
        "CIS_Controls": "16.11 — Leverage Web Application Firewalls",
    },
}


def classify_finding(diagnosis: str) -> str:
    """Classify a diagnosis string into a vulnerability category key."""
    diag_upper = diagnosis.upper()
    if "BFLA" in diag_upper:
        return "BFLA"
    elif "BOLA" in diag_upper and "STATE" in diag_upper:
        return "STATE_MUTATION"
    elif re.search(r'\b(MA|MASS)\b', diag_upper):
        return "MA"
    elif "BOLA" in diag_upper:
        return "BOLA"
    elif "AUTH" in diag_upper:
        return "AUTH"
    return "BOLA"  # Default for generic access control issues


def enrich_finding(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a raw finding dict with OWASP, MITRE ATT&CK, and Compliance metadata.
    Only enriches findings that contain a vulnerability (not SECURE/ANOMALY).
    Returns the enriched result (mutated in-place for efficiency).
    """
    diagnosis = result.get("diagnosis", "")

    if "VULNERABLE" not in diagnosis and "WARNING" not in diagnosis:
        result["owasp"] = None
        result["mitre_attack"] = None
        result["compliance"] = None
        return result

    category = classify_finding(diagnosis)

    # OWASP API Top 10 (2023)
    owasp = OWASP_API_MAP.get(category, OWASP_API_MAP.get("BOLA"))
    result["owasp"] = owasp

    # MITRE ATT&CK
    mitre = MITRE_ATTACK_MAP.get(category, MITRE_ATTACK_MAP.get("BOLA"))
    result["mitre_attack"] = mitre

    # Compliance
    compliance = COMPLIANCE_MAP.get(category, COMPLIANCE_MAP.get("BOLA"))
    result["compliance"] = compliance

    return result


def enrich_all_findings(results: list) -> list:
    """Enrich all findings in a results list."""
    return [enrich_finding(r) for r in results]
