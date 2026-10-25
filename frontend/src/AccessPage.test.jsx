import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';

vi.mock('./api', () => ({
  api: {
    accessUsers: vi.fn(),
    roles: vi.fn(),
    accessAudit: vi.fn(),
  },
}));

import { api } from './api';
import AccessPage from './AccessPage';

const user = {
  id: 1,
  role_authority_rank: 4,
  capabilities: { manage_users: true },
};

beforeEach(() => {
  vi.resetAllMocks();
  api.accessUsers.mockResolvedValue([
    { id: 1, username: 'admin', role: 'super_admin', department: 'HR', team: 'Leadership' },
    { id: 2, username: 'sung-jinwoo', role: 'employee', department: 'HR', team: 'People Operations' },
  ]);
  api.roles.mockResolvedValue([
    { id: 1, name: 'employee', authority_rank: 0 },
    { id: 2, name: 'hr_manager', authority_rank: 2 },
  ]);
  api.accessAudit.mockResolvedValue([]);
});

describe('Assign a role user selection', () => {
  it('shows a selected user’s current role, department, and team', async () => {
    render(<AccessPage user={user} />);

    const userSelect = await screen.findByLabelText('User');
    expect(userSelect.querySelector('option[value="2"]')).toHaveTextContent(
      'sung-jinwoo · employee · HR · People Operations',
    );
    fireEvent.change(userSelect, { target: { value: '2' } });

    expect(screen.getByText('Current assignment: employee · HR · People Operations')).toBeInTheDocument();
  });
});
