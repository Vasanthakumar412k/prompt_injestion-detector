import React, { useEffect, useState } from 'react';
import { api } from './api';

function StatusBadge({ chunk }) {
  const s = chunk.status || (chunk.is_quarantined ? 'quarantined' : 'active');
  if (s === 'quarantined') return <span className="badge badge-danger">🔒 Quarantined</span>;
  if (s === 'pending_judge') return <span className="badge badge-warning">⏳ Pending Review</span>;
  if (s === 'active') return <span className="badge badge-success">✓ Active</span>;
  return <span className="badge badge-neutral">{s}</span>;
}

function ScoreBar({ label, score }) {
  if (score == null) return null;
  const pct = Math.round(score * 100);
  const color = score > 0.7 ? 'var(--danger)' : score > 0.4 ? 'var(--warning)' : 'var(--success)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
      <span style={{ color: 'var(--text-muted)', width: 95 }}>{label}:</span>
      <div style={{ flex: 1, background: 'rgba(255,255,255,0.07)', borderRadius: 4, overflow: 'hidden', height: 6 }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, transition: 'width 0.5s' }} />
      </div>
      <span style={{ color, fontFamily: 'var(--font-mono)', minWidth: 34, textAlign: 'right' }}>{pct}%</span>
    </div>
  );
}

function ChunkCard({ chunk, canRelease, canRetry, onRelease, onRetry }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState('');

  async function handleRelease() {
    setBusy('release');
    await onRelease(chunk.document_id, chunk.id);
    setBusy('');
  }

  async function handleRetry() {
    setBusy('retry');
    await onRetry(chunk.document_id, chunk.id);
    setBusy('');
  }

  return (
    <div className="finding-card" style={{ marginBottom: 10 }}>
      <div className="finding-header" style={{ flexWrap: 'wrap', gap: 6 }}>
        <StatusBadge chunk={chunk} />
        <span className="badge badge-neutral">Doc {chunk.document_id} / Chunk {chunk.chunk_index}</span>
        {chunk.final_reason && (
          <span style={{ fontSize: 11, color: 'var(--text-muted)', flex: 1 }}>
            {chunk.final_reason.slice(0, 80)}
          </span>
        )}
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => setOpen(o => !o)}
          style={{ padding: '2px 8px', fontSize: 11 }}
        >
          {open ? '▲' : '▼'}
        </button>
        {(canRelease || canRetry) && (
          <>
            {canRetry && chunk.status === 'pending_judge' && (
              <button
                id={`retry-chunk-${chunk.id}`}
                className="btn btn-secondary btn-sm"
                disabled={!!busy}
                onClick={handleRetry}
                style={{ fontSize: 11 }}
              >
                {busy === 'retry' ? '⏳' : '🔄 Retry Judge'}
              </button>
            )}
            {canRelease && <button
              id={`release-chunk-${chunk.id}`}
              className="btn btn-danger btn-sm"
              disabled={!!busy}
              onClick={handleRelease}
              style={{ fontSize: 11 }}
            >
              {busy === 'release' ? '⏳' : '🔓 Release'}
            </button>}
          </>
        )}
      </div>
      {open && (
        <div style={{ marginTop: 10 }}>
          <ScoreBar label="DeBERTa" score={chunk.deberta_score} />
          <ScoreBar label="PromptGuard" score={chunk.promptguard_score} />
          {chunk.deberta_label && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
              DeBERTa: <code>{chunk.deberta_label}</code>
              {chunk.promptguard_label && <> | PG: <code>{chunk.promptguard_label}</code></>}
              {chunk.gemini_label && <> | Gemini: <code>{chunk.gemini_label}</code></>}
            </div>
          )}
          {chunk.text_preview && (
            <div className="trace-row" style={{ marginTop: 8 }}>
              <pre style={{ fontSize: 11, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 120, overflow: 'auto', background: 'rgba(0,0,0,0.2)', padding: '6px 10px', borderRadius: 6 }}>
                {chunk.text_preview.slice(0, 400)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function UploadForm({ onUploaded }) {
  const [file, setFile] = useState(null);
  const [confidentiality, setConfidentiality] = useState('internal');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setMsg('');
    try {
      const fd = new FormData();
      fd.append('file', file);
      fd.append('confidentiality', confidentiality);
      const result = await api.uploadDocument(fd);
      setMsg(`✓ Uploaded doc #${result.document_id} — ${result.warnings?.length ? result.warnings.join('; ') : 'clean'}`);
      setFile(null);
      onUploaded?.();
    } catch (e) {
      setMsg('Error: ' + e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form id="upload-document-form" onSubmit={handleSubmit} style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
      <div style={{ flex: 2, minWidth: 200 }}>
        <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>File (txt / pdf / docx)</label>
        <input
          id="doc-file-input"
          type="file"
          accept=".txt,.pdf,.docx"
          onChange={e => setFile(e.target.files[0] || null)}
          style={{ width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, padding: '8px 10px', color: 'var(--text-primary)', fontSize: 13 }}
        />
      </div>
      <div style={{ flex: 1, minWidth: 180 }}>
        <label htmlFor="doc-confidentiality" style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Confidentiality</label>
        <select id="doc-confidentiality" value={confidentiality} onChange={e => setConfidentiality(e.target.value)} style={{ width: '100%', background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '9px 12px', color: 'var(--text-primary)', fontSize: 13 }}>
          {['public', 'internal', 'department', 'confidential'].map(level => <option key={level} value={level}>{level}</option>)}
        </select>
      </div>
      <button id="upload-submit-btn" type="submit" className="btn btn-primary" disabled={busy || !file}>
        {busy ? <><span className="spinner" style={{ width: 14, height: 14 }} /> Uploading…</> : '⬆ Upload'}
      </button>
      {msg && (
        <div className={`alert ${msg.startsWith('Error') ? 'alert-danger' : 'alert-success'}`} style={{ width: '100%', marginTop: 4 }}>
          {msg}
        </div>
      )}
    </form>
  );
}

export default function DocumentsPage({ user }) {
  const [docs, setDocs] = useState([]);
  const [pendingChunks, setPendingChunks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [msg, setMsg] = useState('');
  const [retryingAll, setRetryingAll] = useState(false);

  const canReview = Boolean(user?.capabilities?.view_incidents);
  const canManageDocuments = Boolean(user?.capabilities?.manage_documents);
  const canUpload = canManageDocuments;

  async function loadAll() {
    setLoading(true);
    setError('');
    try {
      const docPromise = api.documents();
      const chunkPromise = canReview ? api.pendingChunks() : Promise.resolve([]);
      const [d, c] = await Promise.all([docPromise, chunkPromise]);
      setDocs(d);
      setPendingChunks(c);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadAll(); }, []);

  async function handleRelease(docId, chunkId) {
    setMsg('');
    try {
      await api.releaseChunk(docId, chunkId);
      setMsg('✓ Chunk released');
      loadAll();
    } catch (e) {
      setMsg('Error: ' + e.message);
    }
  }

  async function handleRetry(docId, chunkId) {
    setMsg('');
    try {
      const r = await api.retryChunkJudge(docId, chunkId);
      setMsg(`✓ Retry complete: ${r.new_status || 'done'}`);
      loadAll();
    } catch (e) {
      setMsg('Error: ' + e.message);
    }
  }

  async function handleRetryAll() {
    setRetryingAll(true);
    setMsg('');
    try {
      const r = await api.retryAllPendingChunks();
      setMsg(`✓ Retry all: ${r.retried} chunks re-judged`);
      loadAll();
    } catch (e) {
      setMsg('Error: ' + e.message);
    } finally {
      setRetryingAll(false);
    }
  }

  if (loading) return <div className="loading-overlay"><span className="spinner" /> Loading…</div>;

  const quarantinedDocs = docs.filter(d => d.is_quarantined);
  const activeDocs = docs.filter(d => !d.is_quarantined);

  return (
    <div className="page-body">
      {error && <div className="alert alert-danger mb-16">⚠️ {error}</div>}
      {msg && (
        <div className={`alert ${msg.startsWith('Error') ? 'alert-danger' : 'alert-success'} mb-16`}>
          {msg}
        </div>
      )}

      {/* Upload form (admin/hr only) */}
      {canUpload && (
        <div className="card mb-24">
          <div className="card-title">⬆ Upload Document</div>
          <UploadForm onUploaded={loadAll} />
        </div>
      )}

      {/* Document list */}
      <div className="section-title">📄 Documents ({docs.length})</div>
      {docs.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">📄</div>
          <div className="empty-state-text">No documents accessible to your role.</div>
        </div>
      ) : (
        <div className="table-wrapper mb-24">
          <table id="documents-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Filename</th>
                <th>Status</th>
                <th>Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {docs.map(d => (
                <tr key={d.id}>
                  <td className="mono">{d.id}</td>
                  <td style={{ fontWeight: 500 }}>{d.filename}</td>
                  <td>
                    {d.is_quarantined
                      ? <span className="badge badge-danger">🔒 Quarantined</span>
                      : <span className="badge badge-success">✓ Active</span>}
                  </td>
                  <td className="text-xs text-muted">{new Date(d.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pending / quarantined chunks (admin/security only) */}
      {canReview && (
        <>
          <div className="flex items-center gap-12 mb-16">
            <div className="section-title" style={{ margin: 0 }}>
              ⚠️ Flagged Chunks ({pendingChunks.length})
            </div>
            {pendingChunks.length > 0 && canReview && (
              <button
                id="retry-all-pending-btn"
                className="btn btn-secondary btn-sm"
                onClick={handleRetryAll}
                disabled={retryingAll}
              >
                {retryingAll ? '⏳ Retrying…' : '🔄 Retry All Pending'}
              </button>
            )}
            <button className="btn btn-secondary btn-sm" onClick={loadAll}>↻ Refresh</button>
          </div>
          {pendingChunks.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">✅</div>
              <div className="empty-state-text">No flagged chunks — all chunks are clean.</div>
            </div>
          ) : (
            pendingChunks.map(c => (
              <ChunkCard
                key={c.id}
                chunk={c}
                canRelease={canManageDocuments}
                canRetry={canReview}
                onRelease={handleRelease}
                onRetry={handleRetry}
              />
            ))
          )}
        </>
      )}
    </div>
  );
}
