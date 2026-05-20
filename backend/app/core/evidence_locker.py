"""
BOLA Strike Enterprise — Evidence Locker (v7.0)
Forensic-grade evidence preservation with SHA-256 integrity hashing.
Addresses: Audit v2.0 Task 2.4
"""
import json, hashlib, os, platform, getpass, datetime, re
from typing import Dict, Any, List

class EvidenceLocker:
    def __init__(self, output_dir: str = "evidence"):
        self.output_dir = output_dir
        self.manifest_entries: List[Dict[str, Any]] = []
        os.makedirs(self.output_dir, exist_ok=True)

    @staticmethod
    def sha256(data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def store_evidence(self, idx: int, result: Dict[str, Any]):
        severity = result.get("severity", "INFO")
        if severity not in ("CRITICAL", "HIGH"):
            return
        eid = f"EVD-{idx:04d}"
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = {"evidence_id": eid, "timestamp": ts, "finding": {
            "path": result.get("path"), "method": result.get("method"),
            "diagnosis": result.get("diagnosis"), "severity": severity,
            "cwe": result.get("cwe"), "diff_ratio": result.get("diff_ratio"),
            "remediation": result.get("remediation"), "curl_poc": result.get("curl_poc", ""),
        }}
        evidence_json = json.dumps(payload, indent=2, ensure_ascii=False)
        evidence_hash = self.sha256(evidence_json)
        safe_path = re.sub(r'[^\w\-_.]', '_', str(result.get("path") or "unknown"))[:60]
        fname = f"{eid}_{result.get('method', 'UNK')}_{safe_path}.json"
        with open(os.path.join(self.output_dir, fname), 'w', encoding='utf-8', newline='\n') as f:
            f.write(evidence_json)
        self.manifest_entries.append({"evidence_id": eid, "file": fname, "sha256": evidence_hash, "timestamp": ts, "severity": severity, "endpoint": f"{result.get('method')} {result.get('path')}"})

    def write_manifest(self, scan_meta: Dict[str, Any] = None) -> str:
        from app.version import __version__
        try:
            user = getpass.getuser()
        except Exception:
            user = "unknown"
        manifest = {"schema_version": "1.0", "tool": "BOLA Strike Enterprise", "tool_version": __version__, "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "chain_of_custody": {"operator_user": user, "operator_host": platform.node(), "operator_os": f"{platform.system()} {platform.release()}"}, "scan_metadata": scan_meta or {}, "evidence_count": len(self.manifest_entries), "evidence": self.manifest_entries}
        manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)
        manifest_hash = self.sha256(manifest_json)
        path = os.path.join(self.output_dir, "manifest.json")
        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(manifest_json)
        with open(path + ".sha256", 'w', encoding='utf-8', newline='\n') as f:
            f.write(f"{manifest_hash}  manifest.json")
        return path

def preserve_evidence(results: List[Dict[str, Any]], target_url: str = "", output_dir: str = "evidence") -> str:
    locker = EvidenceLocker(output_dir=output_dir)
    for idx, result in enumerate(results):
        locker.store_evidence(idx, result)
    return locker.write_manifest(scan_meta={"target_url": target_url, "total_scanned": len(results), "critical_high": sum(1 for r in results if r.get("severity") in ("CRITICAL", "HIGH"))})
