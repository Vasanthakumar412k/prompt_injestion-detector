import React, { useState } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('./api', () => ({
  api: {
    conversations: vi.fn(),
    conversation: vi.fn(),
    createConversation: vi.fn(),
    renameConversation: vi.fn(),
    deleteConversation: vi.fn(),
    chatStream: vi.fn(),
  },
}));

import { api } from './api';
import ChatPage from './ChatPage';
import { ConversationProvider } from './ConversationStore';

const user = { username: 'employee', capabilities: {} };
const firstConversation = {
  id: 1,
  title: 'First chat',
  created_at: '2026-06-01T10:00:00',
  updated_at: '2026-06-01T10:00:00',
};
const firstMessages = [
  { id: 11, role: 'user', content: 'Persist this question', created_at: '2026-06-01T10:00:00' },
  { id: 12, role: 'assistant', content: 'Persist this answer', created_at: '2026-06-01T10:00:01' },
];

function RoutedChat({ show = true, initialConversationId = '1' }) {
  const [conversationId, setConversationId] = useState(initialConversationId);
  return show
    ? <ChatPage
      user={user}
      conversationId={conversationId}
      onNavigate={(_page, id) => setConversationId(id || null)}
    />
    : null;
}

function renderChat(show = true) {
  return render(
    <ConversationProvider>
      <RoutedChat show={show} />
    </ConversationProvider>,
  );
}

beforeEach(() => {
  vi.resetAllMocks();
  localStorage.clear();
  Element.prototype.scrollIntoView = vi.fn();
  vi.spyOn(window, 'prompt').mockReturnValue('Renamed chat');
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  api.conversations.mockResolvedValue({ items: [firstConversation] });
  api.conversation.mockImplementation(async id => ({
    ...firstConversation,
    id: Number(id),
    title: Number(id) === 1 ? firstConversation.title : 'Second chat',
    messages: Number(id) === 1 ? firstMessages : [],
  }));
  api.createConversation.mockResolvedValue({
    id: 2,
    title: 'New chat',
    created_at: '2026-06-01T10:01:00',
    updated_at: '2026-06-01T10:01:00',
  });
  api.renameConversation.mockResolvedValue({ id: 1, title: 'Renamed chat' });
  api.deleteConversation.mockResolvedValue({ id: 1, deleted: true });
});

describe('persistent conversations', () => {
  it('reloads the selected conversation and its messages from the API', async () => {
    renderChat();
    expect(await screen.findByText('Persist this question')).toBeInTheDocument();
    expect(screen.getByText('Persist this answer')).toBeInTheDocument();
    expect(api.conversation).toHaveBeenCalledWith('1');
  });

  it('preserves conversation state when the chat page is unmounted and remounted', async () => {
    const view = renderChat();
    expect(await screen.findByText('Persist this answer')).toBeInTheDocument();
    view.rerender(<ConversationProvider><RoutedChat show={false} /></ConversationProvider>);
    expect(api.conversations).toHaveBeenCalled();
    view.rerender(<ConversationProvider><RoutedChat show /></ConversationProvider>);
    expect(await screen.findByText('Persist this answer')).toBeInTheDocument();
  });

  it('starts a new empty chat without removing the prior conversation', async () => {
    renderChat();
    expect(await screen.findByText('Persist this answer')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /new chat/i }));
    await waitFor(() => expect(api.createConversation).toHaveBeenCalled());
    expect(await screen.findByText('Ask your documents anything')).toBeInTheDocument();
    expect(screen.getAllByText('First chat').length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Second chat')).length).toBeGreaterThan(0);
    expect(screen.queryByText('Persist this answer')).not.toBeInTheDocument();
  });

  it('remembers the selected model for each conversation', async () => {
    const view = renderChat();
    await screen.findByText('Persist this answer');
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'qwen' } });
    expect(screen.getByRole('combobox')).toHaveValue('qwen');
    view.unmount();

    render(
      <ConversationProvider>
        <ChatPage user={user} conversationId="1" onNavigate={vi.fn()} />
      </ConversationProvider>,
    );
    await screen.findByText('Persist this answer');
    expect(screen.getByRole('combobox')).toHaveValue('qwen');
  });

  it('carries the draft model into a newly created conversation', async () => {
    render(
      <ConversationProvider>
        <RoutedChat initialConversationId={null} />
      </ConversationProvider>,
    );
    await screen.findAllByText('First chat');
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'qwen' } });
    fireEvent.click(screen.getByRole('button', { name: /new chat/i }));
    await screen.findAllByText('Second chat');
    expect(screen.getByRole('combobox')).toHaveValue('qwen');
  });

  it('can stop a stalled response, keep its partial text, and continue composing', async () => {
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('Partial answer'));
      },
    });
    api.chatStream.mockResolvedValue({
      ok: true,
      headers: { get: name => name === 'X-Conversation-ID' ? '1' : 'text/plain' },
      body,
    });

    renderChat();
    await screen.findByText('Persist this answer');
    fireEvent.change(document.getElementById('chat-input'), {
      target: { value: 'New question' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));

    expect(await screen.findByText('Partial answer')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Stop generating' })).toBeInTheDocument();
    expect(screen.getByText('Response received · stream active')).toBeInTheDocument();
    fireEvent.change(document.getElementById('chat-input'), {
      target: { value: 'Another question' },
    });
    expect(document.getElementById('chat-input')).toHaveValue('Another question');

    api.conversation.mockResolvedValue({
      ...firstConversation,
      messages: [
        ...firstMessages,
        { id: 13, role: 'user', content: 'New question', status: 'complete' },
        { id: 14, role: 'assistant', content: 'Partial answer', status: 'partial' },
      ],
    });
    fireEvent.click(screen.getByRole('button', { name: 'Stop generating' }));
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Stop generating' })).not.toBeInTheDocument());
    expect(screen.getByText('Partial response')).toBeInTheDocument();
    expect(api.conversation).toHaveBeenCalledWith('1');
  });

  it('shows one assistant row for the initial loading animation', async () => {
    const body = new ReadableStream();
    api.chatStream.mockResolvedValue({
      ok: true,
      headers: { get: name => name === 'X-Conversation-ID' ? '1' : 'text/plain' },
      body,
    });

    renderChat();
    await screen.findByText('Persist this answer');
    fireEvent.change(document.getElementById('chat-input'), {
      target: { value: 'Question while the assistant is loading' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));

    await screen.findByRole('button', { name: 'Stop generating' });
    const assistantRows = document.querySelectorAll('.chat-messages > .message.assistant');
    expect(assistantRows).toHaveLength(2);
    expect(assistantRows[1].querySelector('.typing-dots')).toBeInTheDocument();
    expect(screen.getByText('Generating…')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Stop generating' }));
  });

  it('finishes the UI when the stream ends without waiting for history refresh', async () => {
    api.conversations
      .mockResolvedValueOnce({ items: [firstConversation] })
      .mockReturnValue(new Promise(() => {}));
    api.conversation
      .mockResolvedValueOnce({ ...firstConversation, messages: firstMessages })
      .mockReturnValue(new Promise(() => {}));
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('Finished answer'));
        controller.close();
      },
    });
    api.chatStream.mockResolvedValue({
      ok: true,
      headers: { get: name => name === 'X-Conversation-ID' ? '1' : 'text/plain' },
      body,
    });

    renderChat();
    await screen.findByText('Persist this answer');
    fireEvent.change(document.getElementById('chat-input'), {
      target: { value: 'Question to answer' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));

    expect(await screen.findByText('Finished answer')).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Stop generating' })).not.toBeInTheDocument());
    expect(screen.queryByText('Generating…')).not.toBeInTheDocument();
    expect(screen.queryByText('Partial response')).not.toBeInTheDocument();
    fireEvent.change(document.getElementById('chat-input'), {
      target: { value: 'I can continue now' },
    });
    expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled();
  });

  it('stops the animation and keeps received text when the stream errors', async () => {
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('Partial before disconnect'));
        controller.error(new Error('connection closed'));
      },
    });
    api.chatStream.mockResolvedValue({
      ok: true,
      headers: { get: name => name === 'X-Conversation-ID' ? '1' : 'text/plain' },
      body,
    });
    api.conversation.mockResolvedValue({
      ...firstConversation,
      messages: [
        ...firstMessages,
        { id: 13, role: 'user', content: 'Question', status: 'complete' },
        { id: 14, role: 'assistant', content: 'Partial before disconnect', status: 'partial' },
      ],
    });

    renderChat();
    await screen.findByText('Persist this answer');
    fireEvent.change(document.getElementById('chat-input'), {
      target: { value: 'Question' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));

    expect(await screen.findByText('Partial before disconnect')).toBeInTheDocument();
    expect(await screen.findByText('Partial response')).toBeInTheDocument();
    expect(screen.queryByText('Generating…')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Stop generating' })).not.toBeInTheDocument();
    fireEvent.change(document.getElementById('chat-input'), {
      target: { value: 'Continue after disconnect' },
    });
    expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled();
  });

  it('renames and deletes a conversation in the sidebar', async () => {
    renderChat();
    expect((await screen.findAllByText('First chat')).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button', { name: 'Rename First chat' }));
    expect((await screen.findAllByText('Renamed chat')).length).toBeGreaterThan(0);
    expect(api.renameConversation).toHaveBeenCalledWith(1, 'Renamed chat');
    fireEvent.click(screen.getByRole('button', { name: 'Delete Renamed chat' }));
    await waitFor(() => expect(api.deleteConversation).toHaveBeenCalledWith(1));
    await waitFor(() => expect(screen.queryByText('Renamed chat')).not.toBeInTheDocument());
    expect(window.confirm).toHaveBeenCalled();
  });
});
