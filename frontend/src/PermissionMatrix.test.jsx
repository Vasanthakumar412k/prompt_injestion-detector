/**
 * PermissionMatrix.test.jsx
 * Verifies: matrix renders roles × documents, checkboxes call API correctly,
 * and view-only users see no editable checkboxes.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';

const MOCK_ROLES = [
  { id: 1, name: 'admin', description: 'Administrator' },
  { id: 2, name: 'employee', description: 'Regular employee' },
  { id: 3, name: 'hr', description: 'HR team' },
];

const MOCK_DOCS = [
  { id: 1, filename: 'company_policy.txt', is_quarantined: false, created_at: new Date().toISOString() },
  { id: 2, filename: 'hr_salary_bands.txt', is_quarantined: false, created_at: new Date().toISOString() },
];

const MOCK_PERMS = [
  { id: 1, role_id: 2, role_name: 'employee', document_id: 1, document_filename: 'company_policy.txt', granted_at: '', granted_by: 1 },
];

const MOCK_LOGS = [];

// Mock the api module – factory must not reference outer const variables (hoisting)
vi.mock('./api', () => ({
  api: {
    roles: vi.fn(),
    documents: vi.fn(),
    permissions: vi.fn(),
    permissionLogs: vi.fn(),
    managePermission: vi.fn(),
  },
}));

import RolesPage from './RolesPage';
import { api } from './api';

const MOCK_ROLES = [
  { id: 1, name: 'admin', description: 'Administrator' },
  { id: 2, name: 'employee', description: 'Regular employee' },
  { id: 3, name: 'hr', description: 'HR team' },
];

const MOCK_DOCS = [
  { id: 1, filename: 'company_policy.txt', is_quarantined: false, created_at: new Date().toISOString() },
  { id: 2, filename: 'hr_salary_bands.txt', is_quarantined: false, created_at: new Date().toISOString() },
];

const MOCK_PERMS = [
  { id: 1, role_id: 2, role_name: 'employee', document_id: 1, document_filename: 'company_policy.txt', granted_at: '', granted_by: 1 },
];

const MOCK_LOGS = [];

describe('PermissionMatrix', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.roles.mockResolvedValue(MOCK_ROLES);
    api.documents.mockResolvedValue(MOCK_DOCS);
    api.permissions.mockResolvedValue(MOCK_PERMS);
    api.permissionLogs.mockResolvedValue(MOCK_LOGS);
  });

  it('renders the permissions matrix table', async () => {
    render(<RolesPage user={{ role: 'admin' }} />);
    await waitFor(() => expect(screen.getByText('company_policy.txt')).toBeInTheDocument());
    expect(document.getElementById('permission-matrix-table')).toBeInTheDocument();
  });

  it('shows checked state for existing permission (employee → doc 1)', async () => {
    render(<RolesPage user={{ role: 'admin' }} />);
    await waitFor(() => expect(screen.getByText('company_policy.txt')).toBeInTheDocument());
    const checkbox = document.getElementById('perm-employee-1');
    expect(checkbox).toBeInTheDocument();
    expect(checkbox.checked).toBe(true);
  });

  it('shows unchecked state where permission is absent (employee → doc 2)', async () => {
    render(<RolesPage user={{ role: 'admin' }} />);
    await waitFor(() => expect(screen.getByText('hr_salary_bands.txt')).toBeInTheDocument());
    const checkbox = document.getElementById('perm-employee-2');
    expect(checkbox).toBeInTheDocument();
    expect(checkbox.checked).toBe(false);
  });

  it('calls managePermission with grant when unchecked checkbox is clicked', async () => {
    render(<RolesPage user={{ role: 'admin' }} />);
    await waitFor(() => expect(screen.getByText('hr_salary_bands.txt')).toBeInTheDocument());
    const checkbox = document.getElementById('perm-hr-1');
    fireEvent.click(checkbox);
    await waitFor(() => {
      expect(api.managePermission).toHaveBeenCalledWith('hr', 1, 'grant');
    });
  });

  it('view-only (security role) sees no editable checkboxes', async () => {
    render(<RolesPage user={{ role: 'security' }} />);
    await waitFor(() => expect(screen.getByText('company_policy.txt')).toBeInTheDocument());
    const checkboxes = document.querySelectorAll('input[type="checkbox"]');
    // security role sees read-only indicators, not checkboxes
    expect(checkboxes.length).toBe(0);
  });

  it('permission log table renders', async () => {
    api.permissionLogs.mockResolvedValue([
      { id: 5, role_name: 'hr', document_id: 2, action: 'grant', performed_by: 1, created_at: new Date().toISOString() },
    ]);
    render(<RolesPage user={{ role: 'admin' }} />);
    await waitFor(() => expect(document.getElementById('permission-log-table')).toBeInTheDocument());
    expect(screen.getByText('hr')).toBeInTheDocument();
  });
});
