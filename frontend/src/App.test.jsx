import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

const mocks = vi.hoisted(() => ({
  user: {
    id: 10,
    username: 'tester',
    role: 'super_admin',
    role_authority_rank: 4,
    capabilities: {
      manage_users: true,
      manage_roles: true,
      grant_access: true,
      view_incidents: true,
      run_lab: true,
      view_audit_reports: true,
    },
    features: { chat: true, list_documents: true },
    capability_catalog: [],
  },
  api: {
    conversations: vi.fn(),
    createConversation: vi.fn(),
    renameConversation: vi.fn(),
    deleteConversation: vi.fn(),
  },
}));

vi.mock('./auth', () => ({
  useAuth: () => ({ user: mocks.user, logout: vi.fn() }),
}));

vi.mock('./api', () => ({ api: mocks.api }));

vi.mock('./ChatPage', () => ({
  default: ({ active, conversationId }) => active
    ? <div data-testid="active-chat">{conversationId || 'new chat'}</div>
    : null,
}));

vi.mock('./AdminPage', () => ({ default: () => <div>Security page</div> }));
vi.mock('./AuditorPage', () => ({ default: () => <div>Auditor page</div> }));
vi.mock('./DocumentsPage', () => ({ default: () => <div>Documents page</div> }));
vi.mock('./AccessPage', () => ({ default: () => <div>Access page</div> }));

import App from './App';

const existingConversation = {
  id: 4,
  title: 'Engineering guide',
  created_at: '2026-10-25T10:00:00',
  updated_at: '2026-10-25T10:00:00',
};

beforeEach(() => {
  vi.resetAllMocks();
  localStorage.clear();
  window.history.replaceState({}, '', '/chat');
  mocks.api.conversations.mockResolvedValue({ items: [existingConversation] });
  mocks.api.createConversation.mockResolvedValue({
    id: 5,
    title: 'New chat',
    created_at: '2026-10-25T10:01:00',
    updated_at: '2026-10-25T10:01:00',
  });
});

describe('console sidebar', () => {
  it('shows recent conversations and opens the selected chat', async () => {
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Engineering guide' }));

    expect(await screen.findByTestId('active-chat')).toHaveTextContent('4');
    expect(window.location.pathname).toBe('/chat/4');
  });

  it('creates and opens a chat from the console sidebar', async () => {
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: /new chat/i }));

    await waitFor(() => expect(mocks.api.createConversation).toHaveBeenCalledOnce());
    expect(await screen.findByTestId('active-chat')).toHaveTextContent('5');
    expect(window.location.pathname).toBe('/chat/5');
  });
});
