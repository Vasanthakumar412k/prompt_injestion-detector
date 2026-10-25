import React, { useState } from 'react';
import { useAuth } from './auth';
import LoginPage from './LoginPage';
import ChatPage from './ChatPage';
import AdminPage from './AdminPage';
import AuditorPage from './AuditorPage';
import DocumentsPage from './DocumentsPage';
import AccessPage from './AccessPage';
import { ConversationProvider } from './ConversationStore';
import { useConversations } from './ConversationStore';
import { api } from './api';

const NAV_ITEMS = {
  chat: { id: 'chat', icon: 'chat', label: 'Chat' },
  documents: { id: 'documents', icon: 'documents', label: 'Documents' },
  access: { id: 'access', icon: 'access', label: 'Access control' },
  auditor: { id: 'auditor', icon: 'audit', label: 'Auditor' },
  admin: { id: 'admin', icon: 'security', label: 'Security log' },
};

const NAV_ICON_PATHS = {
  chat: 'M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z',
  documents: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M8 13h8 M8 17h8',
  access: 'M5 11h14v10H5z M8 11V7a4 4 0 0 1 8 0v4',
  audit: 'M3 3v18h18 M7 14l4-4 4 4 6-7',
  security: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
};

function NavigationIcon({ name }) {
  return <svg className="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d={NAV_ICON_PATHS[name]} /></svg>;
}

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
  const {
    conversations, loadingConversations, setConversations, setMessagesFor, modelFor, setModel,
  } = useConversations();
  const [sidebarError, setSidebarError] = useState('');

  async function startNewChat() {
    try {
      setSidebarError('');
      const conversation = await api.createConversation();
      setConversations(previous => [conversation, ...previous.filter(item => item.id !== conversation.id)]);
      setMessagesFor(conversation.id, []);
      setModel(conversation.id, modelFor(null));
      onNavigate('chat', String(conversation.id));
    } catch (error) {
      setSidebarError(error.message || 'Unable to create a new chat.');
    }
  }

  async function renameChat(event, conversation) {
    event.stopPropagation();
    const title = window.prompt('Rename conversation', conversation.title);
    if (!title?.trim()) return;
    try {
      setSidebarError('');
      const updated = await api.renameConversation(conversation.id, title.trim());
      setConversations(previous => previous.map(item =>
        item.id === updated.id ? { ...item, title: updated.title } : item
      ));
    } catch (error) {
      setSidebarError(error.message || 'Unable to rename this chat.');
    }
  }

  async function deleteChat(event, conversation) {
    event.stopPropagation();
    if (!window.confirm(`Delete "${conversation.title}"?`)) return;
    try {
      setSidebarError('');
      await api.deleteConversation(conversation.id);
      setConversations(previous => previous.filter(item => item.id !== conversation.id));
      if (activePage === 'chat' && window.location.pathname === `/chat/${conversation.id}`) {
        onNavigate('chat');
      }
    } catch (error) {
      setSidebarError(error.message || 'Unable to delete this chat.');
    }
  }

  return (
    <div className="sidebar">
      <div className="sidebar-logo">
        <div className="sidebar-logo-icon"><NavigationIcon name="security" /></div>
        <div className="sidebar-logo-text">
          <span className="brand">SecureRAG</span>
          <span className="tagline">Prompt defense</span>
        </div>
      </div>

      <div className="sidebar-section">RAG console</div>
      <nav className="sidebar-nav" aria-label="Main navigation">
        {navItems.map(item => (
          <button
            key={item.id}
            id={`nav-${item.id}`}
            className={`nav-item ${activePage === item.id ? 'active' : ''}`}
            onClick={() => onNavigate(item.id)}
            aria-current={activePage === item.id ? 'page' : undefined}
          >
            <NavigationIcon name={item.icon} />
            <span>{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-section recent-heading">Recent</div>
      <div className="sidebar-recent">
        <button className="sidebar-new-chat" onClick={startNewChat}>＋ New chat</button>
        {sidebarError && <div className="sidebar-error" role="alert">{sidebarError}</div>}
        {loadingConversations && conversations.length === 0 && (
          <div className="sidebar-recent-state">Loading chats…</div>
        )}
        {!loadingConversations && conversations.length === 0 && (
          <div className="sidebar-recent-state">Your recent chats will appear here.</div>
        )}
        {conversations.map(conversation => {
          const selected = activePage === 'chat'
            && window.location.pathname === `/chat/${conversation.id}`;
          return (
            <div key={conversation.id} className={`sidebar-chat${selected ? ' active' : ''}`}>
              <button
                className="sidebar-chat-open"
                onClick={() => onNavigate('chat', String(conversation.id))}
                aria-current={selected ? 'true' : undefined}
                title={conversation.title}
              >
                {conversation.title}
              </button>
              <div className="sidebar-chat-actions">
                <button
                  aria-label={`Rename ${conversation.title}`}
                  title="Rename chat"
                  onClick={event => renameChat(event, conversation)}
                >✎</button>
                <button
                  aria-label={`Delete ${conversation.title}`}
                  title="Delete chat"
                  onClick={event => deleteChat(event, conversation)}
                >×</button>
              </div>
            </div>
          );
        })}
      </div>

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
              showConversationSidebar={false}
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
