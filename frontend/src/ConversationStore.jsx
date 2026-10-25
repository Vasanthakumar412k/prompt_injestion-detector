import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { api } from './api';

const ConversationContext = createContext(null);

function readModels() {
  try {
    return JSON.parse(localStorage.getItem('conversation-models') || '{}');
  } catch {
    return {};
  }
}

export function ConversationProvider({ children }) {
  const [conversations, setConversations] = useState([]);
  const [messagesById, setMessagesById] = useState({});
  const [draftMessages, setDraftMessages] = useState([]);
  const [modelsById, setModelsById] = useState(readModels);
  const [draftModel, setDraftModel] = useState('large');
  const [loadingConversations, setLoadingConversations] = useState(true);
  const [conversationError, setConversationError] = useState('');
  const streamingIds = useRef(new Set());

  const refreshConversations = useCallback(async () => {
    setConversationError('');
    setLoadingConversations(true);
    try {
      const result = await api.conversations();
      setConversations(result.items);
    } catch (error) {
      setConversationError(error.message);
      throw error;
    } finally {
      setLoadingConversations(false);
    }
  }, []);

  useEffect(() => {
    refreshConversations().catch(() => {});
  }, [refreshConversations]);

  const loadConversation = useCallback(async (id) => {
    if (!id || streamingIds.current.has(String(id))) return;
    const conversation = await api.conversation(id);
    setMessagesById(prev => ({ ...prev, [id]: conversation.messages }));
    setConversations(prev => {
      const existing = prev.find(item => item.id === conversation.id);
      const entry = {
        id: conversation.id,
        title: conversation.title,
        created_at: conversation.created_at,
        updated_at: conversation.updated_at,
        last_model: [...conversation.messages].reverse().find(message => message.model)?.model || existing?.last_model,
      };
      return [entry, ...prev.filter(item => item.id !== conversation.id)]
        .sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));
    });
    if (!modelsById[id]) {
      const lastModel = [...conversation.messages].reverse().find(message => message.model)?.model;
      if (lastModel) setModel(id, lastModel);
    }
    return conversation;
  }, [modelsById]);

  const messagesFor = useCallback(id => id ? (messagesById[id] || []) : draftMessages,
    [draftMessages, messagesById]);

  const setMessagesFor = useCallback((id, updater) => {
    if (!id) {
      setDraftMessages(previous => typeof updater === 'function' ? updater(previous) : updater);
      return;
    }
    setMessagesById(previous => ({
      ...previous,
      [id]: typeof updater === 'function' ? updater(previous[id] || []) : updater,
    }));
  }, []);

  const setModel = useCallback((id, model) => {
    if (!id) {
      setDraftModel(model);
      return;
    }
    setModelsById(previous => {
      const next = { ...previous, [id]: model };
      localStorage.setItem('conversation-models', JSON.stringify(next));
      return next;
    });
  }, []);

  const modelFor = useCallback((id) => id ? (modelsById[id] || 'large') : draftModel, [draftModel, modelsById]);

  const beginStreaming = useCallback(id => streamingIds.current.add(String(id)), []);
  const finishStreaming = useCallback(id => streamingIds.current.delete(String(id)), []);

  const value = useMemo(() => ({
    conversations,
    setConversations,
    messagesFor,
    setMessagesFor,
    loadConversation,
    refreshConversations,
    loadingConversations,
    conversationError,
    modelFor,
    setModel,
    beginStreaming,
    finishStreaming,
  }), [
    conversations, messagesFor, setMessagesFor, loadConversation, refreshConversations,
    loadingConversations, conversationError, modelFor, setModel, beginStreaming, finishStreaming,
  ]);

  return <ConversationContext.Provider value={value}>{children}</ConversationContext.Provider>;
}

export function useConversations() {
  const context = useContext(ConversationContext);
  if (!context) throw new Error('useConversations must be used inside ConversationProvider');
  return context;
}
