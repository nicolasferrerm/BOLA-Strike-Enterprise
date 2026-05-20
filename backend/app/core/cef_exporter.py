"""
BOLA Strike Enterprise — CEF Exporter for SIEM Integration (v7.0)
Addresses: Audit v2.0 Task 2.5

Exports findings in ArcSight Common Event Format (CEF) for native ingestion into:
- Splunk (via CEF add-on)
- IBM QRadar
- Microsoft Sentinel
- ArcSight
"""
import datetime
from typing import List, Dict, Any
from app.version import __version__

SEVERITY_MAP = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3, "INFO": 1}

def _escape_cef_header(value: Any) -> str:
    """Escape special CEF characters for headers: backslash, pipe, newlines."""
    return str(value or "").replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r")

def _escape_cef_extension(value: Any) -> str:
    """Escape special CEF characters for extensions: backslash, equals, newlines."""
    return str(value or "").replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")

def finding_to_cef(result: Dict[str, Any], scan_id: str = "N/A") -> str:
    """Convert a single finding to a CEF log line."""
    diagnosis = result.get("diagnosis", "UNKNOWN")
    if "VULNERABLE" not in diagnosis and "WARNING" not in diagnosis:
        return ""
    sev = SEVERITY_MAP.get(result.get("severity", "INFO"), 1)
    method = _escape_cef_extension(result.get("method", "GET"))
    path = _escape_cef_extension(result.get("path", "/"))
    cwe = _escape_cef_extension(result.get("cwe", "N/A"))
    remediation = _escape_cef_extension(result.get("remediation", "N/A"))
    diff = result.get("diff_ratio", 0)
    owasp = result.get("owasp", {}) or {}
    owasp_id = _escape_cef_extension(owasp.get("id", "N/A"))
    mitre = result.get("mitre_attack", {}) or {}
    mitre_tid = _escape_cef_extension(mitre.get("technique", "N/A"))
    ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)

    return (
        f"CEF:0|BOLA Strike|Enterprise Fuzzer|{__version__}|{_escape_cef_header(diagnosis)}|"
        f"API Business Logic Vulnerability Detected|{sev}|"
        f"rt={ts} "
        f"requestMethod={method} "
        f"request={path} "
        f"cs1={cwe} cs1Label=CWE "
        f"cs2={owasp_id} cs2Label=OWASP_API "
        f"cs3={mitre_tid} cs3Label=MITRE_ATT_CK "
        f"cs4={scan_id} cs4Label=ScanID "
        f"cfp1={diff:.2f} cfp1Label=DiffRatio "
        f"msg={remediation}"
    )

def export_cef(results: List[Dict[str, Any]], output_path: str, scan_id: str = "N/A") -> str:
    """Export all vulnerable findings to a CEF log file."""
    lines = [finding_to_cef(r, scan_id) for r in results]
    lines = [l for l in lines if l]
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines) + "\n")
    return output_path
