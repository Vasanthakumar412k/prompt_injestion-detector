/**
 * LoginPage.test.jsx
 * Verifies that the login form renders without any hardcoded credentials,
 * quick-fill demo buttons, or credential hints.
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';

// Mock useAuth so LoginPage can render without a provider
vi.mock('./auth', () => ({
  useAuth: () => ({ login: vi.fn() }),
}));

// global fetch mock – demo/accounts returns empty (no DEMO_MODE)
global.fetch = vi.fn(() =>
  Promise.resolve({ ok: false })
);

import LoginPage from './LoginPage';

describe('LoginPage – no credentials / no quick-fill', () => {
  it('renders username and password inputs', () => {
    render(<LoginPage />);
    expect(document.getElementById('login-username')).toBeInTheDocument();
    expect(document.getElementById('login-password')).toBeInTheDocument();
  });

  it('all inputs start empty', () => {
    render(<LoginPage />);
    const inputs = document.querySelectorAll('input');
    inputs.forEach(inp => expect(inp.value).toBe(''));
  });

  it('no quick-fill demo buttons present', () => {
    render(<LoginPage />);
    const buttons = Array.from(document.querySelectorAll('button'));
    buttons.forEach(btn => {
      const txt = (btn.textContent || '').toLowerCase();
      expect(txt).not.toMatch(/demo|quick.?fill|employee|hr_user|admin_user/);
    });
  });

  it('no hardcoded credential strings in rendered HTML', () => {
    const { container } = render(<LoginPage />);
    const html = container.innerHTML.toLowerCase();
    ['admin123', 'employee123', 'hr123', 'quick-fill', 'quickfill'].forEach(cred => {
      expect(html).not.toContain(cred);
    });
  });
});
