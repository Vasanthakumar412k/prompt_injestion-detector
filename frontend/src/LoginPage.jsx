import React, { useState, useEffect } from 'react';
import { useAuth } from './auth';

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [demoAccounts, setDemoAccounts] = useState([]);

  useEffect(() => {
    // Check if demo hints are exposed by backend (DEMO_MODE=true)
    fetch('/demo/accounts')
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data && data.accounts) {
          setDemoAccounts(data.accounts);
        }
      })
      .catch(() => {});
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(username, password);
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="login-header">
          <div className="login-icon">🛡️</div>
          <div className="login-title">SecureRAG</div>
          <div className="login-subtitle">Security-First Enterprise RAG Platform</div>
        </div>

        {demoAccounts.length > 0 && (
          <div className="login-hint" id="demo-accounts-hint">
            <strong>Demo Accounts:</strong><br />
            {demoAccounts.map(a => `${a.username} (${a.role})`).join(' · ')}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="login-username">Username</label>
            <input
              id="login-username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="Enter your username"
              autoFocus
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="login-password">Password</label>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
            />
          </div>

          {error && (
            <div className="alert alert-danger mb-16" id="login-error">⚠️ {error}</div>
          )}

          <button
            id="login-submit"
            type="submit"
            className="btn btn-primary btn-full"
            disabled={loading}
          >
            {loading ? <><span className="spinner" style={{width:16,height:16}} /> Signing in…</> : '🔐 Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
