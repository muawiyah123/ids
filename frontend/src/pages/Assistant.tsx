import React, { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Bot, Send, Shield, Sparkles, UserRound, Trash2, TriangleAlert, LoaderCircle } from 'lucide-react';
import { assistantApi, type AssistantMessage } from '../services/api';

const WELCOME: AssistantMessage = {
  role: 'assistant',
  content: "Hi, I'm the IDS Sentinel Security Assistant. Ask me about attack types, prevention, incident response, network security, or secure configuration. I can provide general guidance, but I cannot inspect your systems or take actions for you.",
};

const SUGGESTIONS = [
  'How do I investigate a PortScan alert?',
  'How can I protect SSH from brute-force attempts?',
  'What should I do first during a suspected DDoS?',
  'Explain SQL injection and how to prevent it.',
];

function renderInlineMarkdown(text: string): React.ReactNode[] {
  const normalized = text
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<\/?(?:ul|ol)\s*>/gi, '')
    .replace(/<li\s*>/gi, '• ')
    .replace(/<\/li\s*>/gi, ' ');
  const tokens = normalized.split(/(`[^`]*`|\*\*[^*]+\*\*|__[^_]+__|\*[^*]+\*|_[^_]+_)/g);
  return tokens.map((token, index) => {
    if (token.startsWith('`') && token.endsWith('`')) {
      return <code key={index} className="rounded bg-sentinel-bg px-1.5 py-0.5 font-mono text-[0.9em] text-threat-info">{token.slice(1, -1)}</code>;
    }
    if ((token.startsWith('**') && token.endsWith('**')) || (token.startsWith('__') && token.endsWith('__'))) {
      return <strong key={index} className="font-semibold text-sentinel-text">{token.slice(2, -2)}</strong>;
    }
    if ((token.startsWith('*') && token.endsWith('*')) || (token.startsWith('_') && token.endsWith('_'))) {
      return <em key={index}>{token.slice(1, -1)}</em>;
    }
    return token;
  });
}

function tableCells(line: string): string[] {
  return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((cell) => cell.trim());
}

function MarkdownAnswer({ content }: { content: string }) {
  const lines = content.replace(/\r/g, '').split('\n');
  const blocks: React.ReactNode[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index].trim();
    if (!line) { index += 1; continue; }

    if (line.startsWith('```')) {
      index += 1;
      const code: string[] = [];
      while (index < lines.length && !lines[index].trim().startsWith('```')) code.push(lines[index++]);
      if (index < lines.length) index += 1;
      blocks.push(<pre key={`code-${index}`} className="overflow-x-auto rounded-lg bg-sentinel-bg p-3 font-mono text-xs leading-relaxed text-sentinel-text"><code>{code.join('\n')}</code></pre>);
      continue;
    }

    if (line.startsWith('|') && index + 1 < lines.length && /^\|?\s*:?-{3,}/.test(lines[index + 1].trim())) {
      const headers = tableCells(line);
      index += 2;
      const rows: string[][] = [];
      while (index < lines.length && lines[index].trim().startsWith('|')) rows.push(tableCells(lines[index++]));
      blocks.push(
        <div key={`table-${index}`} className="overflow-x-auto rounded-lg border border-sentinel-border">
          <table className="min-w-full border-collapse text-left text-xs">
            <thead className="bg-sentinel-bg text-sentinel-text"><tr>{headers.map((cell, cellIndex) => <th key={cellIndex} className="border-b border-sentinel-border px-3 py-2 font-semibold">{renderInlineMarkdown(cell)}</th>)}</tr></thead>
            <tbody>{rows.map((row, rowIndex) => <tr key={rowIndex} className="odd:bg-sentinel-panel/50">{headers.map((_, cellIndex) => <td key={cellIndex} className="border-b border-sentinel-border/70 px-3 py-2 align-top">{renderInlineMarkdown(row[cellIndex] || '')}</td>)}</tr>)}</tbody>
          </table>
        </div>,
      );
      continue;
    }

    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      const level = heading[1].length;
      const className = level === 1 ? 'text-lg font-semibold text-sentinel-text' : level === 2 ? 'text-base font-semibold text-sentinel-text' : 'text-sm font-semibold text-sentinel-text';
      blocks.push(React.createElement(`h${level}`, { key: `heading-${index}`, className }, renderInlineMarkdown(heading[2])));
      index += 1;
      continue;
    }

    if (/^(---+|\*\*\*+|___+)$/.test(line)) {
      blocks.push(<hr key={`rule-${index}`} className="border-sentinel-border" />);
      index += 1;
      continue;
    }

    const listMatch = line.match(/^(?:[-*+]\s+|\d+[.)]\s+)/);
    if (listMatch) {
      const ordered = /^\d/.test(listMatch[0]);
      const items: React.ReactNode[] = [];
      while (index < lines.length) {
        const itemMatch = lines[index].trim().match(/^(?:[-*+]\s+|\d+[.)]\s+)(.+)$/);
        if (!itemMatch || /^\d/.test(lines[index].trim()) !== ordered) break;
        items.push(<li key={index}>{renderInlineMarkdown(itemMatch[1])}</li>);
        index += 1;
      }
      const List = ordered ? 'ol' : 'ul';
      blocks.push(<List key={`list-${index}`} className={`space-y-1 pl-5 ${ordered ? 'list-decimal' : 'list-disc'}`}>{items}</List>);
      continue;
    }

    if (line.startsWith('>')) {
      const quote: string[] = [];
      while (index < lines.length && lines[index].trim().startsWith('>')) quote.push(lines[index++].trim().replace(/^>\s?/, ''));
      blocks.push(<blockquote key={`quote-${index}`} className="border-l-2 border-sentinel-accent/60 pl-3 text-sentinel-subtle">{quote.map((part) => renderInlineMarkdown(part))}</blockquote>);
      continue;
    }

    const paragraph = [line];
    index += 1;
    while (index < lines.length && lines[index].trim() && !/^(#{1,3})\s|^```|^\||^(?:[-*+]\s+|\d+[.)]\s+)|^(---+|\*\*\*+|___+)|^>/.test(lines[index].trim())) paragraph.push(lines[index++].trim());
    blocks.push(<p key={`paragraph-${index}`}>{renderInlineMarkdown(paragraph.join(' '))}</p>);
  }

  return <div className="space-y-3 break-words text-sm leading-relaxed text-sentinel-text">{blocks}</div>;
}

export function Assistant() {
  const [messages, setMessages] = useState<AssistantMessage[]>([WELCOME]);
  const [input, setInput] = useState('');
  const messagesRef = useRef<HTMLDivElement>(null);
  const status = useQuery({ queryKey: ['assistant-status'], queryFn: assistantApi.status, staleTime: 30_000 });
  const chat = useMutation({
    mutationFn: assistantApi.chat,
    onSuccess: (reply) => setMessages((current) => [...current, { role: 'assistant', content: reply.answer }]),
  });

  useEffect(() => {
    const messageList = messagesRef.current;
    if (messageList) messageList.scrollTop = messageList.scrollHeight;
  }, [messages, chat.isPending]);

  const send = (text = input) => {
    const content = text.trim();
    if (!content || !status.data?.configured || chat.isPending) return;
    const userMessage: AssistantMessage = { role: 'user', content };
    const next = [...messages, userMessage];
    setMessages(next);
    setInput('');
    // Bound provider context and request size; the welcome text is UI-only.
    const history = next.slice(1).slice(-15);
    chat.mutate(history);
  };

  return (
    <div className="flex h-full min-h-0 flex-col p-5 md:p-8">
      <header className="mb-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-3 text-2xl font-bold text-sentinel-text"><Bot size={24} className="text-sentinel-accent" />Security Assistant</h1>
          <p className="mt-1 text-sm text-sentinel-subtle">Cybersecurity answers and defensive guidance for your SOC workflow</p>
        </div>
        <div className="flex items-center gap-3">
          {status.data?.configured && <span className="flex items-center gap-2 rounded-full border border-threat-info/30 bg-threat-info/10 px-3 py-1.5 text-xs text-threat-info"><span className="h-1.5 w-1.5 rounded-full bg-threat-info" />AI configured</span>}
          <button disabled={chat.isPending} onClick={() => { setMessages([WELCOME]); chat.reset(); }} className="btn-secondary inline-flex items-center gap-2 text-xs disabled:opacity-40"><Trash2 size={14} />New chat</button>
        </div>
      </header>

      <div className="mb-4 flex items-start gap-2 rounded-lg border border-sentinel-border bg-sentinel-panel/60 px-4 py-3 text-xs leading-relaxed text-sentinel-subtle">
        <Shield size={15} className="mt-0.5 shrink-0 text-sentinel-accent" />
        <p>Use for authorized defensive work. Answers are general guidance: the assistant cannot see your detections or network unless you describe them, and it cannot block traffic or change systems. Avoid sharing passwords, API keys, personal data, or sensitive logs. Messages are sent to your configured AI provider.</p>
      </div>

      {!status.isLoading && !status.data?.configured && (
        <div className="mb-4 rounded-lg border border-threat-medium/30 bg-threat-medium/10 p-4 text-sm">
          <p className="font-medium text-threat-medium">AI provider is not configured</p>
          <p className="mt-1 text-xs leading-relaxed text-sentinel-subtle">Add your AI key to <code className="text-sentinel-text">AI_API_KEY</code> in the project-root <code className="text-sentinel-text">.env</code>, set <code className="text-sentinel-text">AI_PROVIDER</code>, then restart the backend. See the README setup guide.</p>
        </div>
      )}

      <section className="card flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="flex items-center justify-between border-b border-sentinel-border px-5 py-3">
          <div className="flex items-center gap-2 text-sm font-medium"><Sparkles size={15} className="text-sentinel-accent" />Cybersecurity Q&amp;A</div>
        </div>
        <div ref={messagesRef} className="flex-1 space-y-5 overflow-y-auto p-5 md:p-7">
          {messages.map((message, index) => (
            <div key={`${index}-${message.role}`} className={`flex gap-3 ${message.role === 'user' ? 'flex-row-reverse' : ''}`}>
              <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${message.role === 'assistant' ? 'bg-sentinel-accent/15 text-sentinel-accent' : 'bg-sentinel-muted text-sentinel-text'}`}>
                {message.role === 'assistant' ? <Bot size={17} /> : <UserRound size={16} />}
              </div>
              <div className={`max-w-[min(85%,780px)] rounded-2xl px-4 py-3 ${message.role === 'assistant' ? 'rounded-tl-sm border border-sentinel-border bg-sentinel-panel' : 'rounded-tr-sm bg-sentinel-accent text-white'}`}>
                {message.role === 'assistant' ? <MarkdownAnswer content={message.content} /> : <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">{message.content}</p>}
              </div>
            </div>
          ))}
          {chat.isPending && <div className="flex items-center gap-3 text-sm text-sentinel-subtle"><div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sentinel-accent/15 text-sentinel-accent"><Bot size={17} /></div><LoaderCircle size={15} className="animate-spin" />Thinking…</div>}
          {chat.isError && <div className="ml-11 flex max-w-xl gap-2 rounded-lg border border-threat-high/25 bg-threat-high/5 p-3 text-xs leading-relaxed text-threat-high"><TriangleAlert size={15} className="mt-0.5 shrink-0" />{(chat.error as any)?.response?.data?.detail || 'Could not get a response. Check the backend and AI provider configuration, then try again.'}</div>}
          {messages.length === 1 && <div className="ml-11 mt-2 grid max-w-3xl gap-2 sm:grid-cols-2">{SUGGESTIONS.map((suggestion) => <button key={suggestion} disabled={!status.data?.configured} onClick={() => send(suggestion)} className="rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2.5 text-left text-xs text-sentinel-subtle transition-colors hover:border-sentinel-accent/50 hover:text-sentinel-text disabled:cursor-not-allowed disabled:opacity-50">{suggestion}</button>)}</div>}
        </div>
        <form onSubmit={(event) => { event.preventDefault(); send(); }} className="border-t border-sentinel-border bg-sentinel-surface p-4 md:p-5">
          <div className="flex items-end gap-3 rounded-xl border border-sentinel-border bg-sentinel-bg p-2 focus-within:border-sentinel-accent/60">
            <textarea value={input} onChange={(event) => setInput(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); send(); } }} maxLength={4000} rows={2} placeholder={status.data?.configured ? 'Ask a cybersecurity question… (Enter to send, Shift+Enter for a new line)' : 'Configure the AI provider to start a conversation'} disabled={!status.data?.configured || chat.isPending} className="max-h-40 min-h-[48px] flex-1 resize-y bg-transparent px-2 py-2 text-sm text-sentinel-text outline-none placeholder:text-sentinel-subtle disabled:cursor-not-allowed" />
            <button type="submit" aria-label="Send message" disabled={!input.trim() || !status.data?.configured || chat.isPending} className="btn-primary mb-1 flex h-9 w-9 items-center justify-center rounded-lg p-0 disabled:cursor-not-allowed disabled:opacity-40"><Send size={15} /></button>
          </div>
          <p className="mt-2 text-center text-[10px] text-sentinel-subtle">AI responses can be inaccurate. Validate security advice before applying changes.</p>
        </form>
      </section>
    </div>
  );
}
