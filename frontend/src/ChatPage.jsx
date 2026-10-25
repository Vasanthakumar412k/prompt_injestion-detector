import React, { useState, useRef, useEffect, useCallback } from 'react';
import { api } from './api';
import { useConversations } from './ConversationStore';

const MODELS = [
  { key: 'large', label: 'GPT-OSS 120B', tag: 'openai/gpt-oss-120b' },
  { key: 'medium', label: 'GPT-OSS 20B', tag: 'openai/gpt-oss-20b' },
  { key: 'qwen', label: 'Qwen3.8 27B', tag: 'qwen/qwen3.8-27b' },
];

const BLOCKED_CATEGORIES = ['INJECTION'];

function SecurityTracePanel({ trace, canViewIncidents }) {
  if (!trace) {
    return (
      <div className="trace-panel">
        <div className="trace-panel-header">🔍 Security Trace</div>
        <div className="trace-panel-body">
          <div className="trace-empty">
            <span style={{ fontSize: 32 }}>🛡️</span>
            <span>Security trace will appear after each response</span>
          </div>
        </div>
      </div>
    );
  }

  const { prompt_scan, chunks_used, chunks_dropped, prompt_blocked, block_reason, output_guard } = trace;

  return (
    <div className="trace-panel">
      <div className="trace-panel-header" style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
        <span>🔍 Security Trace</span>
        {trace.request_id && <code style={{ color: 'var(--text-muted)', fontSize: 10 }}>ID {trace.request_id}</code>}
      </div>
      <div className="trace-panel-body">

        {/* Prompt Verdict */}
        <div className="trace-section">
          <div className="trace-section-title">Prompt Scan</div>
          {prompt_blocked ? (
            <div className="badge badge-danger" style={{ marginBottom: 8 }}>🚫 BLOCKED — {block_reason || 'injection detected'}</div>
          ) : (
            <div className="badge badge-success" style={{ marginBottom: 8 }}>✓ ALLOWED</div>
          )}
          {prompt_scan && (
            <>
              <div className="trace-row">
                <span className="trace-key">DeBERTa</span>
                <span className="trace-val">{prompt_scan.deberta?.label || '—'} ({(prompt_scan.deberta?.score * 100 || 0).toFixed(1)}%)</span>
              </div>
              <div className="trace-row">
                <span className="trace-key">PromptGuard</span>
                <span className="trace-val">{prompt_scan.promptguard?.label || '—'} ({(prompt_scan.promptguard?.score * 100 || 0).toFixed(1)}%)</span>
              </div>
              {prompt_scan.gemini_used && (
                <div className="trace-row">
                  <span className="trace-key">Gemini</span>
                  <span className="trace-val">{prompt_scan.gemini?.label || '—'}</span>
                </div>
              )}
              <div className="trace-row">
                <span className="trace-key">Final</span>
                <span className={`trace-val ${prompt_scan.final_label === 'INJECTION' ? 'text-danger' : 'text-success'}`}>
                  {prompt_scan.final_label}
                </span>
              </div>
            </>
          )}
        </div>

        {/* Chunks */}
        {!prompt_blocked && (
          <>
            <div className="trace-section">
              <div className="trace-section-title">Chunks Used ({chunks_used?.length || 0})</div>
              {chunks_used?.length ? chunks_used.map((id, i) => (
                <div key={i} className="trace-chunk-tag">✓ {id}</div>
              )) : <div className="text-muted text-xs">None retrieved</div>}
            </div>

            {chunks_dropped?.length > 0 && (
              <div className="trace-section">
                <div className="trace-section-title">Chunks Dropped ({chunks_dropped.length})</div>
                {chunks_dropped.map((d, i) => (
                  <div key={i} className="trace-chunk-tag dropped">
                    🚫 {d.chroma_id} — {d.reason}
                  </div>
                ))}
              </div>
            )}

            {/* Output guard — employees see only verdict, not matched content */}
            {output_guard && (
              <div className="trace-section">
                <div className="trace-section-title">Output Guard</div>
                <div className="trace-row">
                  <span className="trace-key">Triggered</span>
                  <span className={`trace-val ${output_guard.triggered ? 'text-danger' : 'text-success'}`}>
                    {output_guard.triggered ? '⚠️ Yes' : '✓ No'}
                  </span>
                </div>
                {output_guard.triggered && (
                  <div className="trace-row">
                    <span className="trace-key">Type</span>
                    <span className="trace-val">{output_guard.trigger_type || 'detected'}</span>
                  </div>
                )}
                {/* Only admins/security see matched content details */}
                {canViewIncidents && output_guard.matched && (
                  <div className="trace-row">
                    <span className="trace-key">Match</span>
                    <span className="trace-val mono" style={{ fontSize: 10 }}>{output_guard.matched}</span>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function relativeTime(value) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default function ChatPage({ user, active = true, conversationId, onNavigate }) {
  const store = useConversations();
  const {
    conversations, setConversations, messagesFor, setMessagesFor, loadConversation,
    refreshConversations, loadingConversations, conversationError, modelFor, setModel,
    beginStreaming, finishStreaming,
  } = store;
  const messages = messagesFor(conversationId);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [chatError, setChatError] = useState('');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const bottomRef = useRef(null);
  const textareaRef = useRef(null);
  const activeReaderRef = useRef(null);
  const activeRequestRef = useRef(null);
  const streamStoppedRef = useRef(false);
  const model = modelFor(conversationId);
  const lastTrace = [...messages].reverse().find(message => message.security_trace)?.security_trace || null;

  useEffect(() => {
    if (conversationId) {
      setChatError('');
      loadConversation(conversationId).catch(error => setChatError(error.message));
    }
  }, [conversationId, loadConversation]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendMessage = useCallback(async () => {
    const q = input.trim();
    if (!q || loading) return;

    setInput('');
    setLoading(true);
    setChatError('');
    streamStoppedRef.current = false;
    const controller = new AbortController();
    activeRequestRef.current = controller;

    const userMsg = { role: 'user', content: q, created_at: new Date().toISOString(), status: 'complete' };
    const assistantMsg = { role: 'assistant', content: '', created_at: new Date().toISOString(), status: 'partial' };
    const optimistic = [...messages, userMsg, assistantMsg];
    setMessagesFor(conversationId, optimistic);

    try {
      const response = await api.chatStream(
        q,
        model,
        conversationId ? Number(conversationId) : null,
        controller.signal,
      );
      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: response.statusText }));
        throw new Error(error.detail || 'Chat request failed');
      }

      if (response.headers.get('content-type')?.includes('application/json')) {
        const result = await response.json();
        const id = String(result.conversation_id);
        if (!conversationId) {
          setMessagesFor(null, []);
          onNavigate('chat', id);
        }
        setModel(id, model);
        setMessagesFor(id, result.messages);
        setLoading(false);
        void loadConversation(id).catch(error => setChatError(error.message));
        void refreshConversations().catch(error => setChatError(error.message));
      } else {
        const id = response.headers.get('X-Conversation-ID') || conversationId;
        if (!id) throw new Error('The server did not identify the conversation');
        if (!conversationId) {
          setMessagesFor(String(id), optimistic);
          setMessagesFor(null, []);
          onNavigate('chat', String(id));
        }
        setModel(String(id), model);
        beginStreaming(String(id));

        const reader = response.body.getReader();
        activeReaderRef.current = reader;
        activeRequestRef.current = null;
        const decoder = new TextDecoder();
        let answer = '';
        let streamError = null;
        try {
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            answer += decoder.decode(value, { stream: true });
            setMessagesFor(String(id), previous => previous.map((message, index) =>
              index === previous.length - 1
                ? { ...message, content: answer, status: 'partial' }
                : message
            ));
          }
          answer += decoder.decode();
        } catch (error) {
          if (!streamStoppedRef.current) streamError = error;
        } finally {
          activeReaderRef.current = null;
          reader.releaseLock();
          finishStreaming(String(id));
        }
        setMessagesFor(String(id), previous => previous.map((message, index) =>
          index === previous.length - 1
            ? {
              ...message,
              content: answer,
              status: streamStoppedRef.current || streamError ? 'partial' : 'complete',
            }
            : message
        ));
        setLoading(false);
        if (streamError) setChatError(`Response stream interrupted: ${streamError.message}. Received text has been kept.`);
        void loadConversation(String(id)).catch(error => setChatError(error.message));
        void refreshConversations().catch(error => setChatError(error.message));
      }
    } catch (err) {
      if (!streamStoppedRef.current && err.name !== 'AbortError') setChatError(err.message);
      if (conversationId) {
        void loadConversation(conversationId).catch(error => setChatError(error.message));
      } else {
        void refreshConversations().catch(error => setChatError(error.message));
      }
    } finally {
      activeRequestRef.current = null;
      setLoading(false);
    }
  }, [
    input, model, loading, messages, conversationId, setMessagesFor, setModel,
    onNavigate, beginStreaming, finishStreaming, loadConversation, refreshConversations,
  ]);

  const stopGenerating = useCallback(async () => {
    streamStoppedRef.current = true;
    activeRequestRef.current?.abort();
    const reader = activeReaderRef.current;
    if (reader) {
      try {
        await reader.cancel();
      } catch (error) {
        setChatError(`Unable to stop the response stream: ${error.message}`);
      }
    }
  }, [setChatError]);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  async function startNewChat() {
    try {
      setChatError('');
      const conversation = await api.createConversation();
      setConversations(previous => [conversation, ...previous.filter(item => item.id !== conversation.id)]);
      setMessagesFor(conversation.id, []);
      setModel(conversation.id, modelFor(null));
      setSidebarOpen(false);
      onNavigate('chat', String(conversation.id));
    } catch (error) {
      setChatError(error.message);
    }
  }

  async function renameChat(conversation) {
    const title = window.prompt('Rename conversation', conversation.title);
    if (!title?.trim()) return;
    try {
      const updated = await api.renameConversation(conversation.id, title.trim());
      setConversations(previous => previous.map(item =>
        item.id === updated.id ? { ...item, title: updated.title } : item
      ));
    } catch (error) {
      setChatError(error.message);
    }
  }

  async function deleteChat(conversation) {
    if (!window.confirm(`Delete "${conversation.title}"?`)) return;
    try {
      await api.deleteConversation(conversation.id);
      setConversations(previous => previous.filter(item => item.id !== conversation.id));
      if (String(conversation.id) === String(conversationId)) onNavigate('chat');
    } catch (error) {
      setChatError(error.message);
    }
  }

  return (
    <div className="chat-layout" style={{ display: active ? 'flex' : 'none' }}>
      <aside className={`conversation-sidebar${sidebarOpen ? ' open' : ''}`}>
        <div className="conversation-sidebar-header">
          <button className="btn btn-primary btn-sm" onClick={startNewChat}>＋ New chat</button>
          <button className="conversation-drawer-close" onClick={() => setSidebarOpen(false)} aria-label="Close chats">×</button>
        </div>
        <div className="conversation-list" aria-label="Past chats">
          {loadingConversations && conversations.length === 0 && (
            <div className="conversation-list-state">Loading chats…</div>
          )}
          {!loadingConversations && conversations.length === 0 && (
            <div className="conversation-list-state">Your past chats will appear here.</div>
          )}
          {conversations.map(conversation => (
            <div
              key={conversation.id}
              className={`conversation-item${String(conversation.id) === String(conversationId) ? ' active' : ''}`}
            >
              <button
                className="conversation-select"
                onClick={() => {
                  setSidebarOpen(false);
                  onNavigate('chat', String(conversation.id));
                }}
                title={conversation.title}
              >
                <span className="conversation-title">{conversation.title}</span>
                <span className="conversation-time">{relativeTime(conversation.updated_at)}</span>
              </button>
              <div className="conversation-actions">
                <button aria-label={`Rename ${conversation.title}`} title="Rename" onClick={() => renameChat(conversation)}>✎</button>
                <button aria-label={`Delete ${conversation.title}`} title="Delete" onClick={() => deleteChat(conversation)}>×</button>
              </div>
            </div>
          ))}
        </div>
      </aside>
      {sidebarOpen && <button className="conversation-drawer-backdrop" onClick={() => setSidebarOpen(false)} aria-label="Close chat list" />}
      <div className="chat-main">
        <div className="chat-toolbar">
          <button className="conversation-drawer-open" onClick={() => setSidebarOpen(true)} aria-label="Open chat list">☰</button>
          <span>{conversationId ? conversations.find(item => String(item.id) === String(conversationId))?.title || 'Chat' : 'New chat'}</span>
        </div>
        {conversationError && <div className="alert alert-danger mb-16">{conversationError}</div>}
        {chatError && <div className="alert alert-danger mb-16">{chatError}</div>}
        {/* Messages */}
        <div className="chat-messages">
          {messages.length === 0 && (
            <div className="empty-state" style={{ marginTop: 60 }}>
              <div className="empty-state-icon">💬</div>
              <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8, color: 'var(--text-primary)' }}>
                Ask anything
              </div>
              <div className="empty-state-text">
                Your query will be scanned for prompt injection before reaching the model.
              </div>
            </div>
          )}

          {messages.map((msg, i) => (
            <div key={msg.id || `${msg.role}-${i}`} className={`message ${msg.role} ${msg.blocked ? 'blocked' : ''}`}>
              <div className={`msg-avatar ${msg.role === 'user' ? 'user-av' : 'bot-av'}`}>
                {msg.role === 'user' ? user.username[0].toUpperCase() : '🛡️'}
              </div>
              <div className="msg-body">
                <div className="msg-bubble">
                  {loading && i === messages.length - 1 && msg.role === 'assistant' && !msg.content
                    ? <div className="typing-dots"><span /><span /><span /></div>
                    : msg.content}
                </div>
                <div className="msg-time">
                  {msg.model && msg.role === 'assistant' ? `${msg.model} · ` : ''}
                  {msg.status === 'partial'
                    ? (loading
                      ? (msg.content ? 'Response received · stream active' : 'Generating…')
                      : 'Partial response')
                    : (msg.created_at ? new Date(msg.created_at).toLocaleTimeString() : '')}
                </div>
              </div>
            </div>
          ))}

          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <div className="chat-input-area">
          <div className="model-select-row">
            <span>🤖 Model:</span>
            <select
              id="model-selector"
              value={model}
              onChange={e => setModel(conversationId, e.target.value)}
            >
              {MODELS.map(m => (
                <option key={m.key} value={m.key}>{m.label} — {m.tag}</option>
              ))}
            </select>
          </div>
          <div className="chat-input-row">
            <textarea
              ref={textareaRef}
              id="chat-input"
              className="chat-textarea"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask a question… (Enter to send, Shift+Enter for newline)"
              rows={1}
            />
            {loading ? (
              <button
                id="chat-stop"
                className="chat-send-btn chat-stop-btn"
                onClick={stopGenerating}
                aria-label="Stop generating"
                title="Stop generating"
              >
                ■
              </button>
            ) : (
              <button
                id="chat-send"
                className="chat-send-btn"
                onClick={sendMessage}
                disabled={!input.trim()}
                aria-label="Send"
              >
                ↑
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Security trace */}
      <SecurityTracePanel trace={lastTrace} canViewIncidents={Boolean(user?.capabilities?.view_incidents)} />
    </div>
  );
}
