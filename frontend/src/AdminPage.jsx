import React, { useEffect, useState } from 'react';
import { api } from './api';

function StatCard({ label, value, sub, icon, variant = 'accent' }) {
  return (
    <div className={`stat-card ${variant}`}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

function ActivityChart({ days = [] }) {
  const max = Math.max(1, ...days.map(d => d.scans + d.chats));
  return (
    <div className="card mb-24" aria-label="Live security activity over the last seven days">
      <div className="card-title">📈 Security Activity · Last 7 Days</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, minmax(32px, 1fr))', gap: 10, alignItems: 'end', minHeight: 150, paddingTop: 12 }}>
        {days.map(d => {
          const total = d.scans + d.chats;
          const blocked = d.blocked_scans + d.blocked_chats;
          const height = Math.max(total ? 8 : 2, Math.round(total / max * 110));
          const blockedHeight = total ? Math.round(blocked / total * height) : 0;
          return (
            <div key={d.day} title={`${d.day}: ${d.scans} scans, ${d.chats} chats, ${blocked} blocked`} style={{ textAlign: 'center' }}>
              <div style={{ height, background: 'var(--accent)', borderRadius: '5px 5px 0 0', position: 'relative', minHeight: 2 }}>
                <div style={{ position: 'absolute', inset: 'auto 0 0', height: blockedHeight, background: 'var(--danger)', borderRadius: '0 0 0 0' }} />
              </div>
              <div className="text-xs text-muted" style={{ marginTop: 6 }}>{new Date(`${d.day}T00:00:00`).toLocaleDateString(undefined, { weekday: 'short' })}</div>
              <div className="text-xs">{total}</div>
            </div>
          );
        })}
      </div>
      <div className="text-xs text-muted" style={{ marginTop: 12 }}>Blue: scans and chats · Red segment: blocked requests</div>
    </div>
  );
}

function LogsTable({ logs, type }) {
  if (!logs.length) return <div className="empty-state"><div className="empty-state-text">No {type} logs found</div></div>;

  if (type === 'scan') {
    return (
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Source</th>
              <th>Final</th>
              <th>DeBERTa</th>
              <th>PromptGuard</th>
              <th>Gemini</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {logs.map(l => (
              <tr key={l.id}>
                <td className="mono">{l.id}</td>
                <td><span className="badge badge-neutral">{l.source}</span></td>
                <td>
                  <span className={`badge ${l.final_label === 'INJECTION' ? 'badge-danger' : 'badge-success'}`}>
                    {l.final_label}
                  </span>
                </td>
                <td className="mono text-xs">{l.deberta_label} ({((l.deberta_score || 0) * 100).toFixed(0)}%)</td>
                <td className="mono text-xs">{l.promptguard_label} ({((l.promptguard_score || 0) * 100).toFixed(0)}%)</td>
                <td>{l.gemini_used ? <span className="badge badge-info">{l.gemini_label}</span> : <span className="text-muted">—</span>}</td>
                <td className="text-xs text-muted">{new Date(l.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>User</th>
            <th>Model</th>
            <th>Blocked</th>
            <th>Chunks Used</th>
            <th>Chunks Dropped</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {logs.map(l => (
            <tr key={l.id}>
              <td className="mono">{l.id}</td>
              <td>{l.user_id}</td>
              <td className="mono text-xs">{l.model_used}</td>
              <td>
                {l.prompt_blocked
                  ? <span className="badge badge-danger">🚫 Blocked</span>
                  : <span className="badge badge-success">✓ Allowed</span>}
              </td>
              <td className="mono text-xs">{(l.chunks_used || []).length}</td>
              <td className="mono text-xs">{(l.chunks_dropped || []).length}</td>
              <td className="text-xs text-muted">{new Date(l.created_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function AdminPage() {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [logType, setLogType] = useState('scan');
  const [labRuns, setLabRuns] = useState([]);
  const [tab, setTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [labStarting, setLabStarting] = useState(false);
  const [labMsg, setLabMsg] = useState('');

  useEffect(() => {
    loadAll();
  }, []);

  useEffect(() => {
    api.logs(logType, 50).then(setLogs).catch(() => {});
  }, [logType]);

  async function loadAll() {
    setLoading(true);
    try {
      const [s, lr] = await Promise.all([api.adminStats(), api.labRuns()]);
      setStats(s);
      setLabRuns(lr);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleStartLab() {
    setLabStarting(true);
    setLabMsg('');
    try {
      const r = await api.startLabRun({ splits: ['dev'], max_attacks: 20 });
      setLabMsg(`✓ Lab run started: ${r.run_id}`);
      setTimeout(loadAll, 2000);
    } catch (e) {
      setLabMsg(`Error: ${e.message}`);
    } finally {
      setLabStarting(false);
    }
  }

  if (loading) return <div className="loading-overlay"><span className="spinner" /> Loading dashboard…</div>;
  if (error) return <div className="page-body"><div className="alert alert-danger">⚠️ {error}</div></div>;

  return (
    <div className="page-body">
      <div className="tabs">
        {['overview', 'logs', 'lab'].map(t => (
          <button
            key={t}
            id={`admin-tab-${t}`}
            className={`tab-btn ${tab === t ? 'active' : ''}`}
            onClick={() => setTab(t)}
          >
            {t === 'overview' ? '📊 Overview' : t === 'logs' ? '📋 Logs' : '🔴 Red-Team Lab'}
          </button>
        ))}
      </div>

      {tab === 'overview' && stats && (
        <>
          <div className="stats-grid">
            <StatCard label="Total Scans" value={stats.total_scans} sub={`${stats.recent_scans_7d} this week`} icon="🔍" variant="info" />
            <StatCard label="Blocked" value={stats.blocked_scans} sub={`${stats.block_rate}% block rate`} icon="🚫" variant="danger" />
            <StatCard label="Chat Sessions" value={stats.total_chats} sub={`${stats.recent_chats_7d} this week`} icon="💬" variant="accent" />
            <StatCard label="Chat Blocked" value={stats.blocked_chats} sub={`${stats.chat_block_rate}% rate`} icon="⛔" variant="warning" />
            <StatCard label="Documents" value={stats.total_docs} sub={`${stats.quarantined_docs} quarantined`} icon="📄" variant="info" />
            <StatCard label="Flagged Chunks" value={stats.flagged_chunks} icon="⚠️" variant="warning" />
            <StatCard label="Output Leaks" value={stats.output_leaks} icon="🔓" variant="danger" />
            <StatCard label="Lab Runs" value={stats.lab_runs_done} sub={`${stats.audit_runs_done} audit runs`} icon="🧪" variant="success" />
          </div>

          <ActivityChart days={stats.daily_activity} />

          <div className="section-title">🧪 Red-Team Lab Runs</div>
          {labRuns.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">🧪</div>
              <div className="empty-state-text">No lab runs yet. Start one below.</div>
            </div>
          ) : (
            <div className="table-wrapper mb-24">
              <table>
                <thead>
                  <tr><th>Run ID</th><th>Status</th><th>Progress</th><th>Models</th><th>Started</th></tr>
                </thead>
                <tbody>
                  {labRuns.slice(0, 5).map(r => (
                    <tr key={r.run_id}>
                      <td className="mono text-xs">{r.run_id}</td>
                      <td>
                        <span className={`badge ${r.status === 'done' ? 'badge-success' : r.status === 'error' ? 'badge-danger' : r.status === 'running' ? 'badge-info' : 'badge-neutral'}`}>
                          {r.status}
                        </span>
                      </td>
                      <td>
                        <div style={{ minWidth: 120 }}>
                          <div className="progress-bar">
                            <div className="progress-fill" style={{ width: `${Math.round((r.completed_attacks / Math.max(r.total_attacks, 1)) * 100)}%` }} />
                          </div>
                          <div className="text-xs text-muted" style={{ marginTop: 4 }}>
                            {r.completed_attacks}/{r.total_attacks}
                          </div>
                        </div>
                      </td>
                      <td className="text-xs">{(r.models || []).join(', ')}</td>
                      <td className="text-xs text-muted">{new Date(r.started_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {tab === 'logs' && (
        <>
          <div className="flex items-center gap-8 mb-16">
            <select
              id="log-type-select"
              value={logType}
              onChange={e => setLogType(e.target.value)}
              style={{ width: 'auto' }}
            >
              <option value="scan">Scan Logs</option>
              <option value="chat">Chat Logs</option>
            </select>
            <button className="btn btn-secondary btn-sm" onClick={() => api.logs(logType, 50).then(setLogs)}>↻ Refresh</button>
          </div>
          <LogsTable logs={logs} type={logType} />
        </>
      )}

      {tab === 'lab' && (
        <>
          <div className="flex items-center gap-12 mb-24">
            <button
              id="start-lab-btn"
              className="btn btn-primary"
              onClick={handleStartLab}
              disabled={labStarting}
            >
              {labStarting ? <><span className="spinner" style={{width:16,height:16}} /> Starting…</> : '🚀 Start Lab Run (dev, 20 attacks)'}
            </button>
            <button className="btn btn-secondary" onClick={loadAll}>↻ Refresh</button>
            {labMsg && <span className={labMsg.startsWith('Error') ? 'text-danger' : 'text-success'} style={{ fontSize: 13 }}>{labMsg}</span>}
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr><th>Run ID</th><th>Status</th><th>Progress</th><th>Models</th><th>Configs</th><th>Started</th><th>Error</th></tr>
              </thead>
              <tbody>
                {labRuns.map(r => (
                  <tr key={r.run_id}>
                    <td className="mono text-xs">{r.run_id}</td>
                    <td>
                      <span className={`badge ${r.status === 'done' ? 'badge-success' : r.status === 'error' ? 'badge-danger' : r.status === 'running' ? 'badge-info' : 'badge-neutral'}`}>
                        {r.status}
                      </span>
                    </td>
                    <td>
                      <div style={{ minWidth: 140 }}>
                        <div className="progress-bar">
                          <div className="progress-fill" style={{ width: `${Math.round((r.completed_attacks / Math.max(r.total_attacks, 1)) * 100)}%` }} />
                        </div>
                        <div className="text-xs text-muted" style={{ marginTop: 4 }}>{r.completed_attacks}/{r.total_attacks}</div>
                      </div>
                    </td>
                    <td className="text-xs">{(r.models || []).join(', ')}</td>
                    <td className="text-xs">{(r.configs || []).join(', ')}</td>
                    <td className="text-xs text-muted">{new Date(r.started_at).toLocaleString()}</td>
                    <td className="text-xs text-danger">{r.error ? r.error.slice(0, 60) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
