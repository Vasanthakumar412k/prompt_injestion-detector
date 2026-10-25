import React, { useEffect, useState } from 'react';
import { api } from './api';

function StatusBadge({ action }) {
  return (
    <span className={`badge ${action === 'grant' ? 'badge-success' : 'badge-danger'}`}>
      {action === 'grant' ? '✓ Granted' : '✗ Revoked'}
    </span>
  );
}

export default function RolesPage({ user }) {
  const [roles, setRoles] = useState([]);
  const [docs, setDocs] = useState([]);
  const [permissions, setPermissions] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState('');

  const canEdit = user?.role === 'admin';

  useEffect(() => {
    loadAll();
  }, []);

  async function loadAll() {
    setLoading(true);
    try {
      const [r, d, p, l] = await Promise.all([
        api.roles(),
        api.documents(),
        api.permissions(),
        api.permissionLogs(30),
      ]);
      setRoles(r);
      setDocs(d);
      setPermissions(p);
      setLogs(l);
    } catch (e) {
      setMsg('Error: ' + e.message);
    } finally {
      setLoading(false);
    }
  }

  function hasPermission(roleId, docId) {
    return permissions.some(p => p.role_id === roleId && p.document_id === docId);
  }

  async function toggle(role, doc) {
    const key = `${role.id}_${doc.id}`;
    const has = hasPermission(role.id, doc.id);
    setBusy(key);
    setMsg('');
    try {
      await api.managePermission(role.name, doc.id, has ? 'revoke' : 'grant');
      await loadAll();
      setMsg(`${has ? 'Revoked' : 'Granted'} ${role.name} → ${doc.filename}`);
    } catch (e) {
      setMsg('Error: ' + e.message);
    } finally {
      setBusy('');
    }
  }

  if (loading) return <div className="loading-overlay"><span className="spinner" /> Loading…</div>;

  return (
    <div className="page-body">
      {msg && (
        <div className={`alert ${msg.startsWith('Error') ? 'alert-danger' : 'alert-success'} mb-16`}>
          {msg}
        </div>
      )}

      {/* Permissions Matrix */}
      <div className="section-title">🔐 Role ↔ Document Permissions Matrix</div>
      {!canEdit && (
        <div className="alert alert-info mb-16" style={{ background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 8, padding: '10px 14px', fontSize: 13, color: 'var(--text-secondary)' }}>
          👁 View-only mode. Admin role required to grant or revoke permissions.
        </div>
      )}

      <div className="table-wrapper mb-24">
        <table id="permission-matrix-table">
          <thead>
            <tr>
              <th style={{ minWidth: 120 }}>Role \ Document</th>
              {docs.map(d => (
                <th key={d.id} style={{ fontSize: 11, maxWidth: 120, wordBreak: 'break-word' }}>
                  {d.filename}
                  {d.is_quarantined && <span className="badge badge-danger" style={{ display: 'block', marginTop: 2 }}>🔒</span>}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {roles.map(role => (
              <tr key={role.id}>
                <td style={{ fontWeight: 600, fontSize: 13 }}>
                  <span className="badge badge-neutral">{role.name}</span>
                </td>
                {docs.map(doc => {
                  const has = hasPermission(role.id, doc.id);
                  const key = `${role.id}_${doc.id}`;
                  const isAdminRole = role.name === 'admin';
                  return (
                    <td key={doc.id} style={{ textAlign: 'center' }}>
                      {isAdminRole ? (
                        <span title="Admin has implicit access to all docs" style={{ color: 'var(--text-muted)', fontSize: 18 }}>∞</span>
                      ) : canEdit ? (
                        <input
                          id={`perm-${role.name}-${doc.id}`}
                          type="checkbox"
                          checked={has}
                          disabled={busy === key}
                          onChange={() => toggle(role, doc)}
                          style={{ width: 16, height: 16, cursor: 'pointer', accentColor: has ? 'var(--accent)' : undefined }}
                        />
                      ) : (
                        <span style={{ fontSize: 16 }}>{has ? '✅' : '—'}</span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Audit Log */}
      <div className="section-title">📋 Permission Change Log</div>
      {logs.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">📋</div>
          <div className="empty-state-text">No permission changes recorded yet.</div>
        </div>
      ) : (
        <div className="table-wrapper">
          <table id="permission-log-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Role</th>
                <th>Document</th>
                <th>Action</th>
                <th>By (ID)</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(l => (
                <tr key={l.id}>
                  <td className="mono text-xs">{l.id}</td>
                  <td><span className="badge badge-neutral">{l.role_name}</span></td>
                  <td className="mono text-xs">doc {l.document_id}</td>
                  <td><StatusBadge action={l.action} /></td>
                  <td className="text-muted text-xs">{l.performed_by ?? '—'}</td>
                  <td className="text-muted text-xs">{new Date(l.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
