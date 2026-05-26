"""
BOLA Strike Enterprise — JWT Security Auditor (v7.0)
Addresses: Audit v2.0 Task 2.3

Analyzes JWT tokens for common security misconfigurations:
- Algorithm "none" attack detection
- Weak HMAC key detection
- Expiration validation (replay attack surface)
- Sensitive PII in payload claims
- Missing security claims (iss, aud, iat, exp)
"""
import base64
import json
import time
import logging
import re
import os
import hmac
import hashlib
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

SENSITIVE_CLAIM_PATTERNS = ["email", "phone", "ssn", "address", "password", "secret", "credit", "card", "dob", "birth", "name", "first_name", "last_name", "social", "passport", "license", "bank", "account", "routing", "salary"]
REQUIRED_CLAIMS = ["iss", "aud", "exp", "iat", "sub"]
WEAK_ALGORITHMS = ["none", "None", "NONE", "nOnE"]
DEFAULT_WEAK_HMAC_KEYS = ["secret", "password", "123456", "key", "secret123", "changeme", "test", "admin", "jwt_secret", "123456789"]

def _b64_decode(segment: str) -> dict:
    """Decode a JWT base64url segment to a dict."""
    padding = 4 - len(segment) % 4
    segment += "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(segment)
        return json.loads(decoded)
    except Exception:
        return {}

def audit_jwt(token: str, wordlist_path: str = None) -> Dict[str, Any]:
    """
    Perform a security audit on a JWT token.
    If wordlist_path is provided, attempts offline HMAC cracking.
    """
    findings: List[Dict[str, Any]] = []
    
    # Strip common auth schemes
    token = re.sub(r'^(Bearer|Token|JWT)\s+', '', token, flags=re.IGNORECASE).strip()
    
    parts = token.split(".")
    if len(parts) == 5:
        return {"valid_jwt": False, "is_jwe": True, "error": "Token is a JWE (Encrypted). Cannot audit claims offline.", "findings": []}
    if len(parts) != 3:
        return {"valid_jwt": False, "is_jwe": False, "error": f"Not a valid JWT (expected 3 segments, got {len(parts)})", "findings": []}

    header = _b64_decode(parts[0])
    payload = _b64_decode(parts[1])
    signature = parts[2]
    
    if not header or not payload:
        return {"valid_jwt": False, "is_jwe": False, "error": "Failed to decode JWT header or payload", "findings": []}

    # 1. Algorithm "none" attack
    alg = header.get("alg", "")
    if alg in WEAK_ALGORITHMS:
        findings.append({"id": "JWT-001", "severity": "CRITICAL", "title": "Algorithm 'none' Accepted", "detail": f"JWT uses algorithm '{alg}'. An attacker can forge tokens without a signature.", "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"})

    # 2. Advanced Header Injection (JKU/JWK)
    if "jku" in header or "jwk" in header or "x5u" in header or "x5c" in header:
        findings.append({"id": "JWT-006", "severity": "HIGH", "title": "External Key Injection Surface", "detail": "Header contains jku/jwk/x5u. If the server does not strictly validate the URI/Key, attackers can force the server to trust their own public key.", "cwe": "CWE-348: Use of Less Trusted Source"})

    # 3. typ header check
    typ = header.get("typ", "JWT").upper()
    if typ != "JWT":
        findings.append({"id": "JWT-007", "severity": "LOW", "title": f"Non-standard 'typ' header: {typ}", "detail": "The typ header should explicitly be 'JWT' to prevent cross-JWT confusion attacks (e.g., at+jwt).", "cwe": "CWE-116: Improper Encoding or Escaping of Output"})

    # 4. Weak algorithm / Offline Cracking
    if alg in ("HS256", "HS384", "HS512"):
        cracked = False
        crack_list = DEFAULT_WEAK_HMAC_KEYS
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    crack_list = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.error(f"[JWT Auditor] Failed to load wordlist: {e}")
                
        # Attempt cracking
        target_msg = f"{parts[0]}.{parts[1]}".encode('utf-8')
        sig_bytes = base64.urlsafe_b64decode(signature + "=" * (4 - len(signature) % 4)) if signature else b""
        
        for key in crack_list:
            hash_fn = hashlib.sha384 if alg == "HS384" else hashlib.sha512 if alg == "HS512" else hashlib.sha256
            expected = hmac.new(key.encode('utf-8'), target_msg, hash_fn).digest()
            if hmac.compare_digest(expected, sig_bytes):
                findings.append({"id": "JWT-002", "severity": "CRITICAL", "title": "HMAC Key Cracked", "detail": f"The JWT signature was cracked using a weak key: '{key}'.", "cwe": "CWE-326: Inadequate Encryption Strength"})
                cracked = True
                break
                
        if not cracked:
            findings.append({"id": "JWT-002", "severity": "INFO", "title": f"HMAC Algorithm ({alg})", "detail": "HMAC tokens are vulnerable to offline brute-force. Key was not found in dictionary.", "cwe": "CWE-326"})

    # 3. Missing required claims
    for claim in REQUIRED_CLAIMS:
        if claim not in payload:
            findings.append({"id": f"JWT-003-{claim}", "severity": "LOW", "title": f"Missing Security Claim: '{claim}'", "detail": f"The JWT payload is missing the '{claim}' claim, reducing validation robustness.", "cwe": "CWE-284: Improper Access Control"})

    # 4. Expiration check
    exp = payload.get("exp")
    if exp:
        if isinstance(exp, (int, float)):
            if exp < time.time():
                findings.append({"id": "JWT-004", "severity": "HIGH", "title": "Token is Expired (Replay Attack Surface)", "detail": f"Token expired at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))}. If the API still accepts this token, it is vulnerable to replay attacks.", "cwe": "CWE-613: Insufficient Session Expiration"})

    # 5. PII in payload
    for claim_key in payload.keys():
        if any(pattern in claim_key.lower() for pattern in SENSITIVE_CLAIM_PATTERNS):
            findings.append({"id": f"JWT-005-{claim_key}", "severity": "MEDIUM", "title": f"Sensitive Data in JWT: '{claim_key}'", "detail": f"The claim '{claim_key}' may contain PII. JWTs are base64-encoded (NOT encrypted) and can be decoded by anyone.", "cwe": "CWE-312: Cleartext Storage of Sensitive Information"})

    return {"valid_jwt": True, "is_jwe": False, "header": header, "payload_claims": list(payload.keys()), "algorithm": alg, "findings_count": len(findings), "findings": findings}

def audit_tokens_from_config(users_config: dict, wordlist_path: str = None) -> Dict[str, Any]:
    """Audit all JWT tokens found in the users configuration."""
    report = {}
    for role, cfg in users_config.items():
        token = cfg.get("token") or cfg.get("headers", {}).get("Authorization", "")
        if token:
            if "." in token:
                report[role] = audit_jwt(token, wordlist_path)
                logger.info(f"[JWT Auditor] Audited token for role '{role}': {report[role].get('findings_count', 0)} findings")
    return report
