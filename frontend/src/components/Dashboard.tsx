import React, { useState, useRef } from 'react';

/**
 * BOLA Strike Enterprise Dashboard v7.0 — Phase 4 Polish
 * Full API integration with enriched data display:
 * CVSS scores, OWASP API tags, MITRE ATT&CK, Compliance, Threat Intel
 */

const API_BASE = 'http://localhost:8000/api/v1';

interface CvssData { score: number; rating: string; vector: string; }
interface OWASPData { id: string; name: string; }
interface MITREData { tactic: string; technique: string; technique_name: string; }
interface ThreatIntel { actively_exploited: boolean; escalated: boolean; }
interface ComplianceData { [key: string]: string; }

interface ScanConfig {
  apiKey: string;
  targetUrl: string;
  targetId: string;
  swaggerUrl: string;
  attackerToken: string;
  victimToken: string;
}

interface ScanTaskResult {
  current?: number;
  total?: number;
  total_scanned?: number;
  results?: ScanResult[];
}

interface ScanStatusResponse {
  state: 'PENDING' | 'PROGRESS' | 'SUCCESS' | 'FAILURE';
  result?: ScanTaskResult;
  status?: string;
}

interface ScanStartResponse { task_id: string; }

interface ScanResult {
  path: string; method: string; base_status: number; attack_status: number;
  diff_ratio: number; diagnosis: string; severity: string; cwe: string;
  remediation: string; curl_poc?: string;
  cvss?: CvssData; owasp?: OWASPData; mitre_attack?: MITREData;
  compliance?: ComplianceData; threat_intel?: ThreatIntel;
}

const Dashboard = () => {
  const [scanStatus, setScanStatus] = useState<'IDLE' | 'RUNNING' | 'COMPLETED' | 'ERROR'>('IDLE');
  const [results, setResults] = useState<ScanResult[]>([]);
  const [errorMsg, setErrorMsg] = useState('');
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const pollingRef = useRef<number | null>(null);

  const [config, setConfig] = useState<ScanConfig>({
    apiKey: 'dev-only-change-me-in-production',
    targetUrl: 'http://127.0.0.1:5000',
    targetId: '5050',
    swaggerUrl: '',
    attackerToken: '',
    victimToken: '',
  });

  const stopPolling = () => { if (pollingRef.current) { clearInterval(pollingRef.current); pollingRef.current = null; } };

  const pollStatus = (taskId: string) => {
    pollingRef.current = window.setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/scan/status/${taskId}`, { headers: { 'X-API-Key': config.apiKey } });
        if (!res.ok) throw new Error(`Status check failed: ${res.status}`);
        const data = await res.json() as ScanStatusResponse;
        if (data.state === 'PROGRESS' && data.result) setProgress({ current: data.result.current || 0, total: data.result.total || 0 });
        if (data.state === 'SUCCESS' && data.result) {
          stopPolling(); setScanStatus('COMPLETED');
          setResults(data.result.results || []);
          setProgress({ current: data.result.total_scanned || 0, total: data.result.total_scanned || 0 });
        } else if (data.state === 'FAILURE') { stopPolling(); setScanStatus('ERROR'); setErrorMsg(data.status || 'Scan task failed.'); }
      } catch (error: unknown) {
        stopPolling();
        setScanStatus('ERROR');
        setErrorMsg(error instanceof Error ? error.message : 'Unexpected status error.');
      }
    }, 2000);
  };

  const startScan = async () => {
    setScanStatus('RUNNING'); setResults([]); setErrorMsg(''); setProgress({ current: 0, total: 0 });
    const payload = {
      target_url: config.targetUrl, target_id: config.targetId,
      swagger_url: config.swaggerUrl || undefined,
      users_config: {
        user_a: { name: 'Attacker', token: config.attackerToken || undefined, headers: config.attackerToken ? { Authorization: `Bearer ${config.attackerToken}` } : {} },
        user_b: { name: 'Victim', token: config.victimToken || undefined, headers: config.victimToken ? { Authorization: `Bearer ${config.victimToken}` } : {} },
      },
    };
    try {
      const res = await fetch(`${API_BASE}/scan/start`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': config.apiKey }, body: JSON.stringify(payload) });
      if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error(err.detail || `API returned ${res.status}`); }
      const data = await res.json() as ScanStartResponse; pollStatus(data.task_id);
    } catch (error: unknown) {
      setScanStatus('ERROR');
      setErrorMsg(error instanceof Error ? error.message : 'Unexpected scan error.');
    }
  };

  const vulnCount = results.filter(r => r.diagnosis?.includes('VULNERABLE')).length;
  const warningCount = results.filter(r => r.diagnosis?.includes('WARNING')).length;
  const avgCvss = results.length > 0 ? (results.reduce((s, r) => s + (r.cvss?.score || 0), 0) / results.filter(r => r.cvss?.score).length || 0).toFixed(1) : '—';
  const postureScore = results.length > 0 ? Math.max(0, 100 - (vulnCount * 15 + warningCount * 5)) : 0;

  const sevColor = (s: string) => s === 'CRITICAL' ? 'text-red-500' : s === 'HIGH' ? 'text-orange-500' : s === 'MEDIUM' ? 'text-yellow-500' : 'text-emerald-500';
  const diagColor = (d: string) => d?.includes('VULNERABLE') ? 'text-red-500' : d?.includes('SECURE') ? 'text-emerald-500' : 'text-yellow-500';

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <header className="mb-12 text-center">
        <h1 className="text-5xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-purple-500 via-indigo-500 to-blue-500 mb-4 tracking-tight">
          BOLA Strike Enterprise
        </h1>
        <p className="text-slate-400 text-lg">API Security Posture Management Platform — v7.0.0 Hardened</p>
      </header>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-10">
        <div className="glass-panel p-5 text-center">
          <h3 className="text-slate-400 text-xs font-semibold uppercase tracking-wider mb-1">Posture Score</h3>
          <p className={`text-3xl font-bold ${postureScore >= 75 ? 'text-emerald-400' : postureScore >= 50 ? 'text-yellow-500' : 'text-red-500'}`}>
            {results.length > 0 ? postureScore : '—'}
          </p>
        </div>
        <div className="glass-panel p-5 text-center">
          <h3 className="text-slate-400 text-xs font-semibold uppercase tracking-wider mb-1">Endpoints</h3>
          <p className="text-3xl font-bold text-white">{results.length || '—'}</p>
        </div>
        <div className="glass-panel p-5 text-center">
          <h3 className="text-slate-400 text-xs font-semibold uppercase tracking-wider mb-1">Vulnerabilities</h3>
          <p className="text-3xl font-bold text-red-500">{vulnCount}</p>
        </div>
        <div className="glass-panel p-5 text-center">
          <h3 className="text-slate-400 text-xs font-semibold uppercase tracking-wider mb-1">Warnings</h3>
          <p className="text-3xl font-bold text-yellow-500">{warningCount}</p>
        </div>
        <div className="glass-panel p-5 text-center">
          <h3 className="text-slate-400 text-xs font-semibold uppercase tracking-wider mb-1">Avg CVSS</h3>
          <p className="text-3xl font-bold text-indigo-400">{avgCvss}</p>
        </div>
      </div>

      {/* Scan Configuration */}
      <div className="glass-panel p-8 mb-10">
        <h2 className="text-2xl font-bold mb-6">Scan Configuration</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          {([
            { label: 'API Key (X-API-Key)', key: 'apiKey', type: 'password' },
            { label: 'Target API URL', key: 'targetUrl', type: 'text' },
            { label: 'Target ID (Victim Resource)', key: 'targetId', type: 'text' },
            { label: 'OpenAPI/Swagger URL', key: 'swaggerUrl', type: 'text' },
            { label: 'Attacker JWT Token', key: 'attackerToken', type: 'password' },
            { label: 'Victim JWT Token', key: 'victimToken', type: 'password' },
          ] as Array<{ label: string; key: keyof ScanConfig; type: string }>).map(({ label, key, type }) => (
            <div key={key}>
              <label className="block text-slate-400 text-sm mb-1">{label}</label>
              <input type={type} className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:border-indigo-500 focus:outline-none transition-colors"
                value={config[key]} onChange={e => setConfig(c => ({ ...c, [key]: e.target.value }))}
              />
            </div>
          ))}
        </div>
        <div className="flex items-center gap-4">
          <button onClick={startScan} disabled={scanStatus === 'RUNNING'}
            className="bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-3 rounded-lg font-semibold transition-all duration-300 shadow-lg shadow-indigo-500/30 disabled:opacity-50 disabled:cursor-not-allowed">
            {scanStatus === 'RUNNING' ? '⏳ Fuzzing in progress...' : '🚀 Launch Enterprise Fuzz'}
          </button>
          {scanStatus === 'RUNNING' && progress.total > 0 && (
            <div className="flex items-center gap-3">
              <div className="w-48 bg-slate-800 rounded-full h-2"><div className="bg-indigo-500 h-2 rounded-full transition-all" style={{ width: `${(progress.current / progress.total) * 100}%` }} /></div>
              <span className="text-slate-400 text-sm">{progress.current}/{progress.total}</span>
            </div>
          )}
        </div>
        {errorMsg && <div className="mt-4 p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm"><strong>Error:</strong> {errorMsg}</div>}
      </div>

      {/* Results Table */}
      {results.length > 0 && (
        <div className="glass-panel p-8">
          <h2 className="text-2xl font-bold mb-6">Scan Results ({results.length} endpoints)</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-3 px-3 font-semibold text-xs uppercase">Endpoint</th>
                  <th className="py-3 px-3 font-semibold text-xs uppercase text-center">Method</th>
                  <th className="py-3 px-3 font-semibold text-xs uppercase text-center">CVSS</th>
                  <th className="py-3 px-3 font-semibold text-xs uppercase text-center">Severity</th>
                  <th className="py-3 px-3 font-semibold text-xs uppercase">Diagnosis</th>
                  <th className="py-3 px-3 font-semibold text-xs uppercase text-center">Details</th>
                </tr>
              </thead>
              <tbody>
                {results.map((res, idx) => (
                  <React.Fragment key={idx}>
                    <tr className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors cursor-pointer" onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}>
                      <td className="py-3 px-3 font-mono text-sm text-blue-400">{res.path}</td>
                      <td className="py-3 px-3 text-center"><span className="bg-slate-800 text-xs px-2 py-1 rounded font-bold">{res.method}</span></td>
                      <td className="py-3 px-3 text-center">
                        {res.cvss ? <span className={`font-bold ${res.cvss.score >= 9 ? 'text-red-500' : res.cvss.score >= 7 ? 'text-orange-500' : res.cvss.score >= 4 ? 'text-yellow-500' : 'text-emerald-500'}`}>{res.cvss.score.toFixed(1)}</span> : '—'}
                      </td>
                      <td className={`py-3 px-3 text-center font-bold ${sevColor(res.severity)}`}>{res.severity}</td>
                      <td className={`py-3 px-3 font-bold ${diagColor(res.diagnosis)}`}>{res.diagnosis}</td>
                      <td className="py-3 px-3 text-center"><button className="text-indigo-400 hover:text-indigo-300 text-sm">{expandedRow === idx ? '▲' : '▼'}</button></td>
                    </tr>
                    {expandedRow === idx && (
                      <tr className="border-b-2 border-indigo-500/30">
                        <td colSpan={6} className="p-6 bg-slate-900/50">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                              <h4 className="text-indigo-400 font-bold text-sm uppercase mb-2">Security Context</h4>
                              <div className="space-y-2 text-sm">
                                <div><span className="text-slate-400">CWE:</span> {res.cwe}</div>
                                {res.owasp && <div><span className="text-slate-400">OWASP:</span> <span className="text-indigo-300">{res.owasp.id} — {res.owasp.name}</span></div>}
                                {res.mitre_attack && <div><span className="text-slate-400">MITRE:</span> <span className="text-red-300">{res.mitre_attack.tactic} / {res.mitre_attack.technique}</span></div>}
                                {res.cvss && <div><span className="text-slate-400">CVSS Vector:</span> <code className="text-xs bg-slate-800 px-2 py-0.5 rounded">{res.cvss.vector}</code></div>}
                                <div><span className="text-slate-400">Diff Ratio:</span> {res.diff_ratio !== undefined ? `${Math.round(res.diff_ratio * 100)}%` : '—'}</div>
                                {res.threat_intel?.actively_exploited && <div className="text-red-400 font-bold animate-pulse">⚠ CISA KEV: Actively Exploited Vulnerability</div>}
                              </div>
                            </div>
                            <div>
                              <h4 className="text-indigo-400 font-bold text-sm uppercase mb-2">Remediation</h4>
                              <p className="text-sm text-slate-300">{res.remediation}</p>
                              {res.compliance && (
                                <div className="mt-3">
                                  <h4 className="text-emerald-400 font-bold text-sm uppercase mb-1">Compliance</h4>
                                  <div className="flex flex-wrap gap-1">
                                    {Object.entries(res.compliance).map(([k]) => (
                                      <span key={k} className="text-xs bg-emerald-900/30 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800">{k}</span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
