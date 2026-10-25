import React, { useState } from 'react';
import { useAuth } from './auth';
import LoginPage from './LoginPage';
import ChatPage from './ChatPage';
import AdminPage from './AdminPage';
import AuditorPage from './AuditorPage';
import DocumentsPage from './DocumentsPage';
import AccessPage from './AccessPage';
import { ConversationProvider } from './ConversationStore';

const NAV_ITEMS = {
  chat: { id: 'chat', icon: '💬', label: 'Chat' },
  documents: { id: 'documents', icon: '📄', label: 'Documents' },
  access: { id: 'access', icon: '🔐', label: 'Access' },
  auditor: { id: 'auditor', icon: '🔍', label: 'Auditor' },
  admin: { id: 'admin', icon: '📊', label: 'Security' },
};

function navigationFor(user) {
  const caps = user.capabilities || {};
  const features = user.features || {};
  const items = [];
  if (features.chat) items.push(NAV_ITEMS.chat);
  if (features.list_documents) items.push(NAV_ITEMS.documents);
  if (caps.manage_users || caps.manage_roles || caps.grant_access || caps.request_record_access || caps.view_incidents) items.push(NAV_ITEMS.access);
  if (caps.view_audit_reports || caps.approve_reports) items.push(NAV_ITEMS.auditor);
  if (caps.view_incidents && caps.run_lab) items.push(NAV_ITEMS.admin);
  return items.length ? items : [NAV_ITEMS.chat, NAV_ITEMS.documents];
}

const PAGE_TITLES = {
  chat: { title: 'Secure RAG Chat', subtitle: 'All queries scanned for prompt injection before reaching the model' },
  documents: { title: 'Documents', subtitle: 'Upload and manage documents, review flagged chunks' },
  admin: { title: 'Admin Dashboard', subtitle: 'Security metrics, logs, and red-team lab' },
  auditor: { title: 'Offline Security Auditor', subtitle: 'LLM-powered traffic analysis and finding review' },
  access: { title: 'Access Management', subtitle: 'Manage role assignments, time-limited grants, and access requests' },
};

function Sidebar({ user, activePage, onNavigate, onLogout }) {
  const navItems = navigationFor(user);

  return (
    <div className="sidebar">
      <div className="sidebar-logo">
        <div className="sidebar-logo-icon">🛡️</div>
        <div className="sidebar-logo-text">
          <span className="brand">SecureRAG</span>
          <span className="tagline">Prompt Defense</span>
        </div>
      </div>

      <div className="sidebar-section">Navigation</div>
      {navItems.map(item => (
        <button
          key={item.id}
          id={`nav-${item.id}`}
          className={`nav-item ${activePage === item.id ? 'active' : ''}`}
          onClick={() => onNavigate(item.id)}
        >
          <span className="nav-icon">{item.icon}</span>
          <span>{item.label}</span>
        </button>
      ))}

      <div className="sidebar-footer">
        <div className="user-chip">
          <div className="user-avatar">{user.username[0].toUpperCase()}</div>
          <div className="user-info">
            <div className="user-name">{user.username}</div>
            <div className="user-role">{user.role}</div>
          </div>
          <button
            id="logout-btn"
            className="logout-btn"
            onClick={onLogout}
            title="Sign out"
          >
            ↩
          </button>
        </div>
      </div>
    </div>
  );
}

function Shell({ user }) {
  const { logout } = useAuth();
  const defaultPage = navigationFor(user)[0].id;
  const [route, setRoute] = useState(() => {
    const parts = window.location.pathname.split('/').filter(Boolean);
    if (parts[0] === 'chat') return { page: 'chat', conversationId: parts[1] || null };
    return { page: parts[0] || defaultPage, conversationId: null };
  });
  const page = route.page;

  const navigate = (nextPage, conversationId = null) => {
    const path = nextPage === 'chat'
      ? (conversationId ? `/chat/${conversationId}` : '/chat')
      : `/${nextPage}`;
    window.history.pushState({}, '', path);
    setRoute({ page: nextPage, conversationId });
  };

  React.useEffect(() => {
    const onPopState = () => {
      const parts = window.location.pathname.split('/').filter(Boolean);
      setRoute(parts[0] === 'chat'
        ? { page: 'chat', conversationId: parts[1] || null }
        : { page: parts[0] || defaultPage, conversationId: null });
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, [defaultPage]);

  const meta = PAGE_TITLES[page] || { title: page, subtitle: '' };

  const renderPage = () => {
    switch (page) {
      case 'chat': return <ChatPage user={user} />;
      case 'documents': return <DocumentsPage user={user} />;
      case 'admin': return <AdminPage />;
      case 'auditor': return <AuditorPage />;
      case 'access': return <AccessPage user={user} />;
      default: return <ChatPage user={user} />;
    }
  };

  return (
    <div className="app-shell">
      <Sidebar user={user} activePage={page} onNavigate={navigate} onLogout={logout} />
      <div className="main-content">
        {page !== 'chat' && (
          <div className="page-header">
            <div className="page-title">{meta.title}</div>
            {meta.subtitle && <div className="page-subtitle">{meta.subtitle}</div>}
          </div>
        )}
        <div className={`page-container${page === 'access' ? ' page-container-scroll' : ''}`}>
          <div style={{ display: page === 'chat' ? 'contents' : 'none' }}>
            <ChatPage
              user={user}
              active={page === 'chat'}
              conversationId={route.conversationId}
              onNavigate={navigate}
            />
          </div>
          {page !== 'chat' && renderPage()}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: 'var(--bg-base)', gap: 12, color: 'var(--text-secondary)' }}>
        <span className="spinner" />
        Loading…
      </div>
    );
  }

  if (!user) return <LoginPage />;
  return (
    <ConversationProvider>
      <Shell user={user} />
    </ConversationProvider>
  );
}
