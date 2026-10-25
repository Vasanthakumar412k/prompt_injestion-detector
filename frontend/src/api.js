// api.js – centralised API client (no keys in frontend)
const BASE = '';

function getToken() {
  return localStorage.getItem('token') || '';
}

async function parseJsonResponse(res, path) {
  const contentType = res.headers.get('content-type') || '';
  const body = await res.text();
  try {
    return JSON.parse(body);
  } catch {
    if (contentType.includes('text/html')) {
      throw new Error(
        `Expected JSON from ${path}, but received HTML (HTTP ${res.status}). Check that the API server is running and the Vite proxy is configured.`,
      );
    }
    throw new Error(`Invalid JSON response from ${path} (HTTP ${res.status}).`);
  }
}

async function responseError(res, path) {
  const contentType = res.headers.get('content-type') || '';
  const body = await res.text();
  if (contentType.includes('application/json')) {
    try {
      const error = JSON.parse(body);
      if (error.detail) return new Error(error.detail);
    } catch {
      return new Error(`Invalid error response from ${path} (HTTP ${res.status}).`);
    }
  }
  if (contentType.includes('text/html')) {
    return new Error(
      `API request to ${path} returned HTML (HTTP ${res.status}). Check that the API server is running and the Vite proxy is configured.`,
    );
  }
  return new Error(body || res.statusText || `Request failed (HTTP ${res.status}).`);
}

async function request(method, path, body, isStream = false) {
  const headers = { Authorization: `Bearer ${getToken()}` };
  if (body && !isStream) headers['Content-Type'] = 'application/json';

  const opts = { method, headers };
  if (body) opts.body = typeof body === 'string' ? body : JSON.stringify(body);

  const res = await fetch(BASE + path, opts);

  if (res.status === 401) {
    localStorage.removeItem('token');
    window.location.reload();
    throw new Error('Unauthorized');
  }

  if (!res.ok) {
    throw await responseError(res, path);
  }

  if (isStream) return res;
  return parseJsonResponse(res, path);
}

async function requestForm(method, path, values) {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      Authorization: `Bearer ${getToken()}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams(values),
  });
  if (res.status === 401) {
    localStorage.removeItem('token');
    window.location.reload();
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    throw await responseError(res, path);
  }
  return parseJsonResponse(res, path);
}

export const api = {
  login: (username, password) => {
    const body = new URLSearchParams({ username, password });
    return fetch(BASE + '/auth/login', { method: 'POST', body })
      .then(async r => {
        if (!r.ok) throw new Error('Invalid credentials');
        return parseJsonResponse(r, '/auth/login');
      });
  },
  me: () => request('GET', '/me'),
  chat: (question, model, stream = false, conversation_id = null) =>
    request('POST', '/chat', { question, model, stream, conversation_id }),
  chatStream: (question, model, conversation_id = null, signal) =>
    fetch(BASE + '/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
      body: JSON.stringify({ question, model, stream: true, conversation_id }),
      signal,
    }),
  conversations: (limit = 30, offset = 0) =>
    request('GET', `/conversations?limit=${limit}&offset=${offset}`),
  createConversation: (title = 'New chat') =>
    request('POST', '/conversations', { title }),
  conversation: (id) => request('GET', `/conversations/${id}`),
  renameConversation: (id, title) =>
    request('PATCH', `/conversations/${id}`, { title }),
  deleteConversation: (id) => request('DELETE', `/conversations/${id}`),
  scan: (text, source = 'prompt') => request('POST', '/scan', { text, source }),
  documents: () => request('GET', '/documents'),
  logs: (type = 'scan', limit = 50) => request('GET', `/logs?log_type=${type}&limit=${limit}`),
  adminStats: () => request('GET', '/admin/stats'),
  labRuns: () => request('GET', '/lab/runs'),
  startLabRun: (body) => request('POST', '/lab/run', body),
  labRunStatus: (runId) => request('GET', `/lab/runs/${runId}`),
  auditRuns: () => request('GET', '/audit/runs'),
  triggerAudit: (body = {}) => request('POST', '/audit/run', body),
  auditRunDetail: (runId) => request('GET', `/audit/runs/${runId}`),
  auditState: () => request('GET', '/audit/state'),
  approveAudit: (runId) => request('POST', `/audit/runs/${runId}/approve`),
  exportAudit: (runId, format = 'json') => {
    return fetch(BASE + `/audit/runs/${runId}/export?format=${format}`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    }).then(async res => {
      if (!res.ok) {
        throw await responseError(res, `/audit/runs/${runId}/export`);
      }
      return format === 'json'
        ? parseJsonResponse(res, `/audit/runs/${runId}/export`)
        : res.text();
    });
  },
  roles: () => request('GET', '/roles'),
  permissions: () => request('GET', '/permissions'),
  managePermission: (role_name, document_id, action) =>
    request('POST', '/permissions', { role_name, document_id, action }),
  permissionLogs: (limit = 50) => request('GET', `/permissions/logs?limit=${limit}`),
  uploadDocument: (formData) => {
    return fetch(BASE + '/documents', {
      method: 'POST',
      headers: { Authorization: `Bearer ${getToken()}` },
      body: formData,
    }).then(async res => {
      if (!res.ok) {
        throw await responseError(res, '/documents');
      }
      return parseJsonResponse(res, '/documents');
    });
  },
  pendingChunks: () => request('GET', '/chunks/pending'),
  releaseChunk: (docId, chunkId, adminNote = '') =>
    request('POST', `/documents/${docId}/chunks/${chunkId}/release`, { admin_note: adminNote }),
  retryChunkJudge: (docId, chunkId) =>
    request('POST', `/documents/${docId}/chunks/${chunkId}/retry-judge`),
  retryAllPendingChunks: () => request('POST', '/chunks/retry-pending'),
  accessUsers: () => request('GET', '/access/users'),
  assignUserRole: (userId, role_name, reason) =>
    request('PATCH', `/users/${userId}/role`, { role_name, reason }),
  assignRoleCapability: (role, capability, enabled, reason) =>
    request('PATCH', `/roles/${encodeURIComponent(role)}/capabilities`, { capability, enabled, reason }),
  accessGrants: (state = 'active') => request('GET', `/access-grants?state=${encodeURIComponent(state)}`),
  createAccessGrant: (grantee_id, document_id, reason, duration_hours) =>
    request('POST', '/access-grants', { grantee_id, document_id, reason, duration_hours }),
  revokeAccessGrant: (grantId, reason) => requestForm('DELETE', `/access-grants/${grantId}`, { reason }),
  requestRecordAccess: (document_id, reason) =>
    requestForm('POST', `/access-grants/request?document_id=${encodeURIComponent(document_id)}`, { reason }),
  recordAccessRequests: () => request('GET', '/access-grants/requests'),
  approveRecordAccess: (requestId, duration_hours = 8) =>
    requestForm('POST', `/access-grants/requests/${requestId}/approve`, { duration_hours }),
  accessAudit: () => request('GET', '/access-audit'),
};
