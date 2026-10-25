import React, { useEffect, useState } from 'react';
import { api } from './api';

const SEVERITY_COLORS = {
  high: 'danger',
  medium: 'warning',
  low: 'success',
};

const CATEGORY_ICONS = {
  injection_attempt: '💉',
  possible_leak: '🔓',
  over_blocking: '⛔',
  suspicious_pattern: '🔎',
  weak_refusal: '⚠️',
  other: '❓',
};

function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`finding-card ${finding.severity}`} id={`finding-${finding.id}`}>
      <div className="finding-header">
        <span className={`badge badge-${SEVERITY_COLORS[finding.severity]}`}>
          {finding.severity.toUpperCase()}
        </span>
        <span className="badge badge-neutral">
          {CATEGORY_ICONS[finding.category] || '❓'} {finding.category}
        </span>
        <span className={`badge ${finding.status === 'confirmed' ? 'badge-danger' : finding.status === 'not_reproduced' ? 'badge-success' : 'badge-warning'}`}>
          {finding.status}
        </span>
        <span className="finding-id">{finding.finding_uid}</span>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)' }}>
          conf: {((finding.confidence || 0) * 100).toFixed(0)}%
        </span>
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => setOpen(o => !o)}
          style={{ padding: '2px 8px', fontSize: 11 }}
        >
          {open ? '▲' : '▼'}
        </button>
      </div>
      <div className="finding-explanation">{finding.explanation}</div>
      {open && (
        <>
          {finding.suggested_action && (
            <div className="finding-action">💡 {finding.suggested_action}</div>
          )}
          {finding.evidence_log_ids?.length > 0 && (
            <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Evidence: {finding.evidence_log_ids.join(', ')}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function AuditRunDetail({ runId, onBack }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionMsg, setActionMsg] = useState('');
  const [approving, setApproving] = useState(false);
  const [exporting, setExporting] = useState('');

  useEffect(() => {
    api.auditRunDetail(runId)
      .then(setDetail)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [runId]);

  async function handleApprove() {
    setApproving(true);
    setActionMsg('');
    try {
      await api.approveAudit(runId);
      setActionMsg('✓ Run approved — you can now export the report.');
      // reload detail
      const d = await api.auditRunDetail(runId);
      setDetail(d);
    } catch (e) {
      setActionMsg('Error: ' + e.message);
    } finally {
      setApproving(false);
    }
  }

  async function handleExport(format) {
    setExporting(format);
    setActionMsg('');
    try {
      const content = await api.exportAudit(runId, format);
      if (format === 'json') {
        const blob = new Blob([JSON.stringify(content, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `audit_${runId}.json`; a.click();
        URL.revokeObjectURL(url);
      } else {
        const blob = new Blob([content], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `audit_${runId}.html`; a.click();
        URL.revokeObjectURL(url);
      }
      setActionMsg(`✓ ${format.toUpperCase()} report downloaded.`);
    } catch (e) {
      setActionMsg('Error: ' + e.message);
    } finally {
      setExporting('');
    }
  }

  if (loading) return <div className="loading-overlay"><span className="spinner" /> Loading…</div>;
  if (error) return <div className="alert alert-danger">⚠️ {error}</div>;
  if (!detail) return null;

  const summary = detail.summary || {};
  const sc = summary.severity_counts || {};
  const isApproved = detail.is_approved;

  return (
    <div>
      <div className="flex items-center gap-12 mb-24">
        <button className="btn btn-secondary btn-sm" onClick={onBack}>← Back</button>
        <h2 style={{ fontSize: 16, fontWeight: 600 }}>Audit Run: <span className="mono" style={{ fontSize: 13 }}>{runId}</span></h2>
        <span className={`badge badge-${detail.status === 'completed' ? 'success' : detail.status === 'error' ? 'danger' : 'warning'}`}>
          {detail.status}
        </span>
        {isApproved && <span className="badge badge-success">✓ Approved</span>}
      </div>

      {/* Action bar: approve + export */}
      <div className="card mb-24">
        <div className="card-title">📤 Review & Export</div>
        <div className="flex items-center gap-12" style={{ flexWrap: 'wrap' }}>
          {!isApproved ? (
            <button
              id={`approve-audit-${runId}`}
              className="btn btn-primary"
              onClick={handleApprove}
              disabled={approving || detail.status !== 'completed'}
            >
              {approving ? <><span className="spinner" style={{ width: 14, height: 14 }} /> Approving…</> : '✓ Approve Report'}
            </button>
          ) : (
            <>
              <button
                id={`export-json-${runId}`}
                className="btn btn-secondary"
                onClick={() => handleExport('json')}
                disabled={!!exporting}
              >
                {exporting === 'json' ? '⏳' : '⬇ Export JSON'}
              </button>
              <button
                id={`export-html-${runId}`}
                className="btn btn-secondary"
                onClick={() => handleExport('html')}
                disabled={!!exporting}
              >
                {exporting === 'html' ? '⏳' : '🌐 Export HTML'}
              </button>
            </>
          )}
          {actionMsg && (
            <span className={actionMsg.startsWith('Error') ? 'text-danger' : 'text-success'} style={{ fontSize: 13 }}>
              {actionMsg}
            </span>
          )}
        </div>
        {!isApproved && detail.status === 'completed' && (
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>
            ⚠️ A reviewer must approve this run before the pseudonymized report can be exported.
          </p>
        )}
      </div>

      {/* Summary stats */}
      <div className="stats-grid mb-24">
        <div className="stat-card info">
          <div className="stat-label">Logs Analyzed</div>
          <div className="stat-value">{detail.total_logs_analyzed}</div>
        </div>
        <div className="stat-card danger">
          <div className="stat-label">High Severity</div>
          <div className="stat-value">{sc.high || 0}</div>
        </div>
        <div className="stat-card warning">
          <div className="stat-label">Medium Severity</div>
          <div className="stat-value">{sc.medium || 0}</div>
        </div>
        <div className="stat-card success">
          <div className="stat-label">Low Severity</div>
          <div className="stat-value">{sc.low || 0}</div>
        </div>
      </div>

      {/* Recommendations */}
      {summary.top_recommendations?.length > 0 && (
        <div className="card mb-24">
          <div className="card-title">💡 Top Recommendations</div>
          <ul style={{ paddingLeft: 20, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 2 }}>
            {summary.top_recommendations.map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </div>
      )}

      {/* Findings */}
      <div className="section-title">🔎 Findings ({detail.findings.length})</div>
      {detail.findings.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">✅</div>
          <div className="empty-state-text">No findings — traffic looks clean.</div>
        </div>
      ) : (
        detail.findings.map(f => <FindingCard key={f.id} finding={f} />)
      )}
    </div>
  );
}

export default function AuditorPage() {
  const [runs, setRuns] = useState([]);
  const [state, setState] = useState(null);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState(false);
  const [msg, setMsg] = useState('');
  const [selectedRun, setSelectedRun] = useState(null);
  const [force, setForce] = useState(false);

  useEffect(() => {
    loadAll();
  }, []);

  async function loadAll() {
    setLoading(true);
    try {
      const [r, s] = await Promise.all([api.auditRuns(), api.auditState()]);
      setRuns(r);
      setState(s);
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function handleTrigger() {
    setTriggering(true);
    setMsg('');
    try {
      await api.triggerAudit({ force });
      setMsg('✓ Audit run triggered — refresh in a few seconds.');
      setTimeout(loadAll, 3000);
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setTriggering(false);
    }
  }

  if (selectedRun) {
    return (
      <div className="page-body">
        <AuditRunDetail runId={selectedRun} onBack={() => setSelectedRun(null)} />
      </div>
    );
  }

  return (
    <div className="page-body">
      {/* Header controls */}
      <div className="card mb-24">
        <div className="card-title">⚙️ Offline Security Auditor</div>
        {state && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12, marginBottom: 16 }}>
            <div className="trace-row"><span className="trace-key">Auditor Model</span><span className="trace-val mono">{state.auditor_model}</span></div>
            <div className="trace-row"><span className="trace-key">Schedule</span><span className="trace-val">{state.schedule_mode} / {state.interval_hours}h</span></div>
            <div className="trace-row"><span className="trace-key">Sampling</span><span className="trace-val">{(state.sampling_rate * 100).toFixed(0)}%</span></div>
            <div className="trace-row"><span className="trace-key">Last Run</span><span className="trace-val text-xs">{state.last_run_at ? new Date(state.last_run_at).toLocaleString() : 'Never'}</span></div>
          </div>
        )}
        <div className="flex items-center gap-12">
          <button
            id="trigger-audit-btn"
            className="btn btn-primary"
            onClick={handleTrigger}
            disabled={triggering}
          >
            {triggering
              ? <><span className="spinner" style={{width:16,height:16}} /> Running…</>
              : '▶ Run Audit Now'}
          </button>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={force}
              onChange={e => setForce(e.target.checked)}
              id="force-audit-check"
            />
            Force (re-analyze already-audited logs)
          </label>
          <button className="btn btn-secondary btn-sm" onClick={loadAll}>↻ Refresh</button>
          {msg && <span className={msg.startsWith('Error') ? 'text-danger' : 'text-success'} style={{ fontSize: 13 }}>{msg}</span>}
        </div>
      </div>

      {loading ? (
        <div className="loading-overlay"><span className="spinner" /> Loading audit runs…</div>
      ) : (
        <>
          <div className="section-title">📋 Audit Run History</div>
          {runs.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">🔍</div>
              <div className="empty-state-text">No audit runs yet. Trigger one above.</div>
            </div>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Run ID</th>
                    <th>Status</th>
                    <th>Logs</th>
                    <th>Findings</th>
                    <th>High/Med/Low</th>
                    <th>Model</th>
                    <th>Date</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map(r => (
                    <tr key={r.run_id}>
                      <td className="mono text-xs">{r.run_id}</td>
                      <td>
                        <span className={`badge badge-${r.status === 'completed' ? 'success' : r.status === 'error' ? 'danger' : r.status === 'running' ? 'info' : 'neutral'}`}>
                          {r.status}
                        </span>
                      </td>
                      <td>{r.total_logs_analyzed}</td>
                      <td style={{ fontWeight: 600 }}>{r.total_findings}</td>
                      <td>
                        <span className="text-danger">{r.severity_counts?.high || 0}</span>
                        {' / '}
                        <span className="text-warning">{r.severity_counts?.medium || 0}</span>
                        {' / '}
                        <span className="text-success">{r.severity_counts?.low || 0}</span>
                      </td>
                      <td className="mono text-xs">{r.auditor_model}</td>
                      <td className="text-xs text-muted">{new Date(r.created_at).toLocaleString()}</td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          id={`view-audit-${r.run_id}`}
                          onClick={() => setSelectedRun(r.run_id)}
                        >
                          View →
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
