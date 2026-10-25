import React, { useEffect, useMemo, useState } from 'react';
import { api } from './api';

function Select({ label, value, onChange, children }) {
  return <label className="access-field">{label}<select value={value} onChange={onChange}>{children}</select></label>;
}

export default function AccessPage({ user }) {
  const caps = user?.capabilities || {};
  const capabilities = user?.capability_catalog || [];
  const canManageUsers = Boolean(caps.manage_users);
  const canManageRoles = Boolean(caps.manage_roles);
  const canGrant = Boolean(caps.grant_access);
  const canRequest = Boolean(caps.request_record_access);
  const canApprove = Boolean(caps.approve_record_access);
  const canViewAudit = Boolean(caps.view_incidents || caps.manage_users || caps.manage_roles);
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [documents, setDocuments] = useState([]);
  const [grants, setGrants] = useState([]);
  const [grantState, setGrantState] = useState('active');
  const [audit, setAudit] = useState([]);
  const [requests, setRequests] = useState([]);
  const [selectedUser, setSelectedUser] = useState('');
  const [selectedRole, setSelectedRole] = useState('');
  const [roleReason, setRoleReason] = useState('');
  const [selectedGrantee, setSelectedGrantee] = useState('');
  const [selectedDocument, setSelectedDocument] = useState('');
  const [grantReason, setGrantReason] = useState('');
  const [duration, setDuration] = useState(Math.min(8, user.max_access_grant_hours || 24));
  const [requestDocumentId, setRequestDocumentId] = useState('');
  const [requestReason, setRequestReason] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const assignableUsers = useMemo(() => users.filter((item) => item.id !== user.id), [users, user.id]);
  const selectedRoleUser = assignableUsers.find((item) => String(item.id) === selectedUser);

  async function load() {
    setError('');
    const work = [];
    if (canManageUsers || canGrant) work.push(api.accessUsers().then(setUsers));
    if (canManageUsers) work.push(api.roles().then(setRoles));
    if (canGrant) {
      work.push(api.documents().then(setDocuments));
      work.push(api.accessGrants(grantState).then(setGrants));
    }
    if (canApprove) work.push(api.recordAccessRequests().then(setRequests));
    if (canViewAudit) work.push(api.accessAudit().then(setAudit));
    const results = await Promise.allSettled(work);
    const failed = results.find((result) => result.status === 'rejected');
    if (failed) setError(failed.reason?.message || 'Some access information could not be loaded.');
  }

  useEffect(() => { load(); }, [grantState]);

  async function submit(action) {
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage('Access changes saved.');
      await load();
    } catch (err) {
      setError(err.message || 'The access change was denied.');
    } finally {
      setBusy(false);
    }
  }

  const assignRole = (event) => {
    event.preventDefault();
    if (!selectedUser || !selectedRole || !roleReason.trim()) return;
    submit(() => api.assignUserRole(selectedUser, selectedRole, roleReason.trim()));
  };

  const createGrant = (event) => {
    event.preventDefault();
    if (!selectedGrantee || !selectedDocument || !grantReason.trim()) return;
    submit(() => api.createAccessGrant(Number(selectedGrantee), Number(selectedDocument), grantReason.trim(), Number(duration)));
  };

  const requestAccess = (event) => {
    event.preventDefault();
    if (!requestDocumentId || !requestReason.trim()) return;
    submit(() => api.requestRecordAccess(Number(requestDocumentId), requestReason.trim()));
    setRequestReason('');
  };

  return (
    <div className="page-body access-page">
      {message && <div className="alert alert-success mb-16">{message}</div>}
      {error && <div className="alert alert-danger mb-16">{error}</div>}

      {canManageUsers && (
        <section className="card mb-24">
          <div className="card-title">👥 Assign a role</div>
          <p className="access-help">Changes apply to the selected user. You cannot change your own role or assign authority above your own.</p>
          <form className="access-form" onSubmit={assignRole}>
            <Select label="User" value={selectedUser} onChange={(event) => setSelectedUser(event.target.value)}>
              <option value="">Choose a user</option>
              {assignableUsers.map((item) => (
                <option value={item.id} key={item.id}>
                  {item.username} · {item.role} · {item.department || 'No department'} · {item.team || 'No team'}
                </option>
              ))}
            </Select>
            <p className="access-help" aria-live="polite">
              {selectedRoleUser
                ? `Current assignment: ${selectedRoleUser.role} · ${selectedRoleUser.department || 'No department'} · ${selectedRoleUser.team || 'No team'}`
                : 'Select a user to see their current role, department, and team.'}
            </p>
            <Select label="Role" value={selectedRole} onChange={(event) => setSelectedRole(event.target.value)}>
              <option value="">Choose a role</option>
              {roles.filter((role) => role.authority_rank <= user.role_authority_rank).map((role) => <option value={role.name} key={role.id}>{role.name}</option>)}
            </Select>
            <label className="access-field">Reason<input value={roleReason} onChange={(event) => setRoleReason(event.target.value)} required maxLength={500} /></label>
            <button className="btn btn-primary" disabled={busy || !selectedUser || !selectedRole || !roleReason.trim()}>Save role</button>
          </form>
        </section>
      )}

      {canManageRoles && (
        <section className="card mb-24">
          <div className="card-title">🔐 Role capabilities</div>
          <p className="access-help">Only capabilities you hold can be delegated. Scope stays at the role’s configured level.</p>
          <div className="access-role-list">
            {roles.filter((role) => role.authority_rank < user.role_authority_rank).map((role) => (
              <div className="access-role-row" key={role.id}>
                <strong>{role.name}</strong>
                <div className="access-cap-grid">
                  {capabilities.map((capability) => {
                    const enabled = Boolean(role.capabilities?.[capability]);
                    const canChange = !enabled || Boolean(caps[capability]);
                    return <label key={capability} className={canChange ? '' : 'access-disabled'}>
                      <input type="checkbox" checked={enabled} disabled={!canChange || busy} onChange={(event) => submit(() => api.assignRoleCapability(role.name, capability, event.target.checked, `Policy change by ${user.username}`))} />
                      {capability.replaceAll('_', ' ')}{role.capabilities?.[capability] ? ` · ${role.capabilities[capability]}` : ''}
                    </label>;
                  })}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {canGrant && (
        <>
          <section className="card mb-24">
            <div className="card-title">⏱ Temporary document access</div>
            <p className="access-help">Grants expire automatically when their end time passes. Your scope and the target user’s scope are checked by the server.</p>
            <form className="access-form" onSubmit={createGrant}>
              <Select label="User" value={selectedGrantee} onChange={(event) => setSelectedGrantee(event.target.value)}>
                <option value="">Choose a user</option>
                {assignableUsers.map((item) => <option value={item.id} key={item.id}>{item.username} · {item.role}</option>)}
              </Select>
              <Select label="Document" value={selectedDocument} onChange={(event) => setSelectedDocument(event.target.value)}>
                <option value="">Choose a readable document</option>
                {documents.map((doc) => <option value={doc.id} key={doc.id}>{doc.filename} · {doc.confidentiality}</option>)}
              </Select>
              <label className="access-field">Duration (hours)<input type="number" min="0.25" max={user.max_access_grant_hours || 24} step="0.25" value={duration} onChange={(event) => setDuration(event.target.value)} required /><small>Maximum: {user.max_access_grant_hours || 24} hours</small></label>
              <label className="access-field">Reason<input value={grantReason} onChange={(event) => setGrantReason(event.target.value)} required maxLength={500} /></label>
              <button className="btn btn-primary" disabled={busy || !selectedGrantee || !selectedDocument || !grantReason.trim()}>Create grant</button>
            </form>
          </section>

          <section className="card mb-24">
            <div className="access-section-head">
              <div className="card-title">📋 Access grants</div>
              <Select label="Show" value={grantState} onChange={(event) => setGrantState(event.target.value)}>
                {['active', 'expired', 'revoked', 'all'].map((state) => <option key={state} value={state}>{state}</option>)}
              </Select>
            </div>
            {grants.length === 0 ? <p className="access-help">No {grantState} grants in your scope.</p> : (
              <div className="access-table-wrap"><table className="data-table"><thead><tr><th>Grant</th><th>User</th><th>Document</th><th>Reason</th><th>Expires</th><th>Status</th><th /></tr></thead>
                <tbody>{grants.map((grant) => <tr key={grant.id}><td>#{grant.id}</td><td>{users.find((item) => item.id === grant.grantee_id)?.username || grant.grantee_id}</td><td>{documents.find((doc) => doc.id === grant.document_id)?.filename || `Document ${grant.document_id}`}</td><td>{grant.reason}</td><td>{new Date(grant.expires_at).toLocaleString()}</td><td>{grant.state}</td><td>{grant.state === 'active' && <button className="btn btn-danger btn-sm" disabled={busy} onClick={() => {
                  const reason = window.prompt('Reason for revoking this grant:');
                  if (reason?.trim()) submit(() => api.revokeAccessGrant(grant.id, reason.trim()));
                }}>Revoke</button>}</td></tr>)}</tbody>
              </table></div>
            )}
          </section>
        </>
      )}

      {canRequest && (
        <section className="card mb-24">
          <div className="card-title">📝 Request record access</div>
          <p className="access-help">Enter the document ID shown in a report or provided by your department. Your request is recorded for an authorized approver.</p>
          <form className="access-form" onSubmit={requestAccess}>
            <label className="access-field">Document ID<input type="number" min="1" value={requestDocumentId} onChange={(event) => setRequestDocumentId(event.target.value)} required /></label>
            <label className="access-field">Reason<input value={requestReason} onChange={(event) => setRequestReason(event.target.value)} required maxLength={500} /></label>
            <button className="btn btn-primary" disabled={busy || !requestDocumentId || !requestReason.trim()}>Submit request</button>
          </form>
        </section>
      )}

      {canApprove && (
        <section className="card mb-24">
          <div className="card-title">📨 Pending record-access requests</div>
          {requests.length === 0 ? <p className="access-help">There are no pending requests in your approval scope.</p> : (
            <div className="access-table-wrap"><table className="data-table"><thead><tr><th>Requester</th><th>Document</th><th>Reason</th><th>Requested</th><th /></tr></thead>
              <tbody>{requests.map((item) => <tr key={item.request_id}><td>{item.requester} · {item.department}</td><td>{item.filename} · #{item.document_id}</td><td>{item.reason}</td><td>{new Date(item.created_at).toLocaleString()}</td><td><button className="btn btn-primary btn-sm" disabled={busy} onClick={() => submit(() => api.approveRecordAccess(item.request_id, 8))}>Approve for 8 hours</button></td></tr>)}</tbody>
            </table></div>
          )}
        </section>
      )}

      {canViewAudit && (
        <section className="card mb-24">
          <div className="card-title">🧾 Access audit trail</div>
          {audit.length === 0 ? <p className="access-help">No access events have been recorded.</p> : (
            <div className="access-table-wrap"><table className="data-table"><thead><tr><th>Time</th><th>Actor</th><th>Target</th><th>Action</th><th>Reason</th><th>Result</th></tr></thead>
              <tbody>{audit.map((row) => <tr key={row.id}><td>{new Date(row.created_at).toLocaleString()}</td><td>{row.actor_id}</td><td>{row.target_id ?? '—'}</td><td>{row.action}</td><td>{row.reason || '—'}</td><td>{row.result}</td></tr>)}</tbody>
            </table></div>
          )}
        </section>
      )}
    </div>
  );
}
