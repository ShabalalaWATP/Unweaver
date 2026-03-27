import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  Bot,
  Brain,
  Loader2,
  Maximize2,
  MessageSquare,
  Minimize2,
  Send,
  User,
  X,
} from 'lucide-react';
import type {
  AnalystChatMessage,
  AnalystChatRetrievedFile,
  SampleDetail,
} from '@/types';
import * as api from '@/services/api';
import { useToast } from '@/components/common/Toast';

type ChatState = 'closed' | 'compact' | 'expanded';

interface AnalystChatProps {
  sample: SampleDetail | null;
}

interface ProviderMeta {
  provider: string;
  model: string;
  contextTruncated: boolean;
  workspaceSearchEnabled: boolean;
  workspaceFileCount: number;
  retrievedFiles: AnalystChatRetrievedFile[];
}

const s = {
  launcher: {
    position: 'absolute',
    right: '24px',
    bottom: '24px',
    zIndex: 50,
    display: 'inline-flex',
    alignItems: 'center',
    gap: '10px',
    padding: '12px 20px',
    borderRadius: '999px',
    background: 'var(--accent)',
    color: 'var(--bg-primary)',
    fontSize: '14px',
    fontWeight: 700,
    boxShadow: '0 18px 36px rgba(88, 166, 255, 0.28)',
    transition: 'transform 0.2s ease, box-shadow 0.2s ease',
  } as React.CSSProperties,
  panel: {
    position: 'absolute',
    zIndex: 50,
    display: 'flex',
    flexDirection: 'column',
    background: '#0a0a12',
    border: '1px solid #1a1a2e',
    boxShadow: '0 28px 90px rgba(0, 0, 0, 0.55)',
    transition: 'all 0.28s ease',
    overflow: 'hidden',
  } as React.CSSProperties,
  panelCompact: {
    right: '24px',
    bottom: '24px',
    width: '420px',
    height: '550px',
    borderRadius: '20px',
  } as React.CSSProperties,
  panelExpanded: {
    left: '15%',
    right: '15%',
    top: '8%',
    bottom: '8%',
    borderRadius: '22px',
  } as React.CSSProperties,
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '12px',
    padding: '12px 16px',
    borderBottom: '1px solid #1a1a2e',
    flexShrink: 0,
  } as React.CSSProperties,
  headerLeft: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    minWidth: 0,
  } as React.CSSProperties,
  headerIcon: {
    width: '28px',
    height: '28px',
    borderRadius: '10px',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'rgba(88, 166, 255, 0.14)',
    color: 'var(--accent-bright)',
    flexShrink: 0,
  } as React.CSSProperties,
  headerTitle: {
    fontSize: '14px',
    fontWeight: 700,
    color: 'var(--text-primary)',
  } as React.CSSProperties,
  headerSubtitle: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    maxWidth: '220px',
  } as React.CSSProperties,
  headerControls: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    flexShrink: 0,
  } as React.CSSProperties,
  iconBtn: {
    width: '30px',
    height: '30px',
    borderRadius: '10px',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'var(--text-muted)',
    transition: 'background 0.15s ease, color 0.15s ease',
  } as React.CSSProperties,
  messages: {
    flex: 1,
    overflowY: 'auto',
    padding: '14px 16px',
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
  } as React.CSSProperties,
  emptyState: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    textAlign: 'center',
    gap: '12px',
    height: '100%',
    padding: '28px 18px',
  } as React.CSSProperties,
  emptyIcon: {
    width: '48px',
    height: '48px',
    borderRadius: '14px',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'rgba(88, 166, 255, 0.1)',
    color: 'var(--accent-bright)',
  } as React.CSSProperties,
  emptyTitle: {
    fontSize: '14px',
    fontWeight: 600,
    color: 'var(--text-primary)',
  } as React.CSSProperties,
  emptyText: {
    fontSize: '12px',
    color: 'var(--text-muted)',
    maxWidth: '300px',
    lineHeight: 1.6,
  } as React.CSSProperties,
  promptList: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '8px',
    justifyContent: 'center',
    marginTop: '4px',
  } as React.CSSProperties,
  promptChip: {
    fontSize: '11px',
    padding: '6px 12px',
    borderRadius: '999px',
    background: 'var(--bg-secondary)',
    color: 'var(--text-muted)',
    transition: 'background 0.15s ease, color 0.15s ease',
  } as React.CSSProperties,
  row: {
    display: 'flex',
    gap: '8px',
  } as React.CSSProperties,
  rowAssistant: {
    justifyContent: 'flex-start',
  } as React.CSSProperties,
  rowUser: {
    justifyContent: 'flex-end',
  } as React.CSSProperties,
  bubbleIcon: {
    width: '24px',
    height: '24px',
    borderRadius: '8px',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
    marginTop: '2px',
  } as React.CSSProperties,
  assistantIcon: {
    background: 'rgba(88, 166, 255, 0.1)',
    color: 'var(--accent-bright)',
  } as React.CSSProperties,
  userIcon: {
    background: 'var(--bg-secondary)',
    color: 'var(--text-muted)',
  } as React.CSSProperties,
  bubble: {
    maxWidth: '85%',
    borderRadius: '14px',
    padding: '12px 14px',
    fontSize: '13px',
    lineHeight: 1.65,
    overflowWrap: 'anywhere',
  } as React.CSSProperties,
  assistantBubble: {
    background: '#12121f',
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
  userBubble: {
    background: 'rgba(88, 166, 255, 0.15)',
    color: 'var(--text-primary)',
  } as React.CSSProperties,
  textBlock: {
    whiteSpace: 'pre-wrap',
  } as React.CSSProperties,
  markdownRoot: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
  } as React.CSSProperties,
  paragraph: {
    margin: 0,
    whiteSpace: 'pre-wrap',
  } as React.CSSProperties,
  heading1: {
    margin: 0,
    fontSize: '18px',
    lineHeight: 1.25,
    fontWeight: 700,
    color: 'var(--text-primary)',
    letterSpacing: '-0.02em',
    paddingBottom: '6px',
    borderBottom: '1px solid rgba(88, 166, 255, 0.16)',
  } as React.CSSProperties,
  heading2: {
    margin: 0,
    fontSize: '15px',
    lineHeight: 1.3,
    fontWeight: 700,
    color: 'var(--text-primary)',
    letterSpacing: '-0.01em',
  } as React.CSSProperties,
  heading3: {
    margin: 0,
    fontSize: '13px',
    lineHeight: 1.35,
    fontWeight: 700,
    color: 'var(--accent-bright)',
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
  } as React.CSSProperties,
  blockquote: {
    margin: 0,
    padding: '10px 12px',
    borderLeft: '3px solid var(--accent)',
    background: 'rgba(88, 166, 255, 0.08)',
    borderRadius: '0 12px 12px 0',
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
  divider: {
    border: 0,
    borderTop: '1px solid rgba(88, 166, 255, 0.12)',
    margin: '2px 0',
  } as React.CSSProperties,
  list: {
    margin: 0,
    paddingLeft: '18px',
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
  } as React.CSSProperties,
  listItem: {
    margin: 0,
  } as React.CSSProperties,
  link: {
    color: 'var(--accent-bright)',
    textDecoration: 'underline',
    textUnderlineOffset: '2px',
  } as React.CSSProperties,
  tableOuter: {
    overflowX: 'auto',
    borderRadius: '12px',
    border: '1px solid #1a1a2e',
    background: '#0f1119',
  } as React.CSSProperties,
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    minWidth: '360px',
  } as React.CSSProperties,
  tableHeadCell: {
    textAlign: 'left',
    padding: '10px 12px',
    fontSize: '11px',
    fontWeight: 700,
    color: 'var(--text-primary)',
    background: 'rgba(88, 166, 255, 0.08)',
    borderBottom: '1px solid #1a1a2e',
    whiteSpace: 'nowrap',
  } as React.CSSProperties,
  tableCell: {
    padding: '10px 12px',
    fontSize: '12px',
    color: 'var(--text-secondary)',
    borderTop: '1px solid rgba(255, 255, 255, 0.04)',
    verticalAlign: 'top',
  } as React.CSSProperties,
  tableRowEven: {
    background: 'rgba(255, 255, 255, 0.015)',
  } as React.CSSProperties,
  inlineCode: {
    color: 'var(--accent-bright)',
    background: '#1a1a2e',
    padding: '2px 5px',
    borderRadius: '6px',
    fontSize: '11px',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  codeWrap: {
    position: 'relative',
    marginTop: '10px',
  } as React.CSSProperties,
  codeLanguage: {
    position: 'absolute',
    top: '8px',
    left: '10px',
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    color: 'var(--accent-bright)',
    pointerEvents: 'none',
  } as React.CSSProperties,
  copyBtn: {
    position: 'absolute',
    top: '8px',
    right: '8px',
    fontSize: '10px',
    padding: '4px 8px',
    borderRadius: '8px',
    background: 'var(--bg-hover)',
    color: 'var(--text-muted)',
    border: '1px solid #1a1a2e',
  } as React.CSSProperties,
  codeBlock: {
    margin: 0,
    padding: '30px 12px 12px',
    borderRadius: '12px',
    background: '#0c0c14',
    border: '1px solid #1a1a2e',
    overflowX: 'auto',
    fontFamily: 'var(--font-mono)',
    fontSize: '11px',
    lineHeight: 1.6,
    color: 'var(--text-primary)',
    whiteSpace: 'pre',
  } as React.CSSProperties,
  loadingRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '4px 0',
    color: 'var(--text-muted)',
    fontSize: '12px',
  } as React.CSSProperties,
  contextStrip: {
    marginTop: '10px',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    padding: '10px 12px',
    borderRadius: '14px',
    background: 'rgba(88, 166, 255, 0.06)',
    border: '1px solid rgba(88, 166, 255, 0.12)',
  } as React.CSSProperties,
  contextMeta: {
    fontSize: '10px',
    lineHeight: 1.5,
    color: 'var(--text-muted)',
  } as React.CSSProperties,
  contextChipList: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '8px',
  } as React.CSSProperties,
  contextChip: {
    maxWidth: '100%',
    display: 'inline-flex',
    alignItems: 'center',
    padding: '5px 10px',
    borderRadius: '999px',
    background: 'rgba(10, 10, 18, 0.76)',
    border: '1px solid rgba(88, 166, 255, 0.12)',
    color: 'var(--text-secondary)',
    fontSize: '10px',
    fontFamily: 'var(--font-mono)',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  } as React.CSSProperties,
  composerShell: {
    padding: '12px 16px',
    borderTop: '1px solid #1a1a2e',
    flexShrink: 0,
  } as React.CSSProperties,
  composerRow: {
    display: 'flex',
    alignItems: 'flex-end',
    gap: '8px',
  } as React.CSSProperties,
  textarea: {
    flex: 1,
    minHeight: '40px',
    maxHeight: '120px',
    resize: 'none',
    borderRadius: '14px',
    padding: '11px 14px',
    background: '#12121f',
    border: '1px solid #1a1a2e',
    color: 'var(--text-primary)',
    fontSize: '13px',
    lineHeight: 1.55,
    outline: 'none',
    overflowY: 'auto',
    fontFamily: 'var(--font-ui)',
  } as React.CSSProperties,
  sendBtn: {
    width: '40px',
    height: '40px',
    borderRadius: '14px',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'var(--accent)',
    color: 'var(--bg-primary)',
    flexShrink: 0,
    transition: 'opacity 0.15s ease, transform 0.15s ease',
  } as React.CSSProperties,
  footer: {
    marginTop: '8px',
    display: 'flex',
    justifyContent: 'space-between',
    gap: '12px',
    fontSize: '10px',
    color: 'var(--text-muted)',
  } as React.CSSProperties,
} as const;

const QUICK_PROMPTS = [
  'Summarize what changed',
  'Explain the most suspicious behavior',
  'What is still unresolved?',
];

function sanitizeAssistantText(content: string): string {
  return content
    .replace(/<think>[\s\S]*?<\/think>/gi, '')
    .replace(/^thinking:.*$/gim, '')
    .trim();
}

function formatRetrievedSource(source: AnalystChatRetrievedFile['source']): string {
  switch (source) {
    case 'recovered_bundle':
      return 'recovered';
    case 'original_bundle':
      return 'bundle';
    default:
      return 'archive';
  }
}

function AssistantMessage({
  content,
  loading,
}: {
  content: string;
  loading: boolean;
}) {
  const toast = useToast();

  if (!content && loading) {
    return (
      <div style={s.loadingRow}>
        <Loader2 size={14} className="animate-spin" color="var(--accent-bright)" />
        <span>Responding…</span>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <div style={s.markdownRoot}>
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          components={{
            h1: ({ children }) => <h1 style={s.heading1}>{children}</h1>,
            h2: ({ children }) => <h2 style={s.heading2}>{children}</h2>,
            h3: ({ children }) => <h3 style={s.heading3}>{children}</h3>,
            h4: ({ children }) => <h3 style={s.heading3}>{children}</h3>,
            p: ({ children }) => <p style={s.paragraph}>{children}</p>,
            ul: ({ children }) => (
              <ul style={s.list}>
                {children}
              </ul>
            ),
            ol: ({ children }) => (
              <ol style={s.list}>
                {children}
              </ol>
            ),
            li: ({ children }) => <li style={s.listItem}>{children}</li>,
            blockquote: ({ children }) => <blockquote style={s.blockquote}>{children}</blockquote>,
            hr: () => <hr style={s.divider} />,
            a: ({ href, children }) => (
              <a href={href} target="_blank" rel="noreferrer" style={s.link}>
                {children}
              </a>
            ),
            em: ({ children }) => <em style={{ color: 'var(--text-primary)' }}>{children}</em>,
            strong: ({ children }) => <strong style={{ color: 'var(--text-primary)' }}>{children}</strong>,
            table: ({ children }) => (
              <div style={s.tableOuter}>
                <table style={s.table}>{children}</table>
              </div>
            ),
            thead: ({ children }) => <thead>{children}</thead>,
            tbody: ({ children }) => <tbody>{children}</tbody>,
            tr: ({ children, ...props }) => {
              const isHeaderRow = Boolean(props.node?.children?.some((child: any) => child.tagName === 'th'));
              return (
                <tr style={isHeaderRow ? undefined : s.tableRowEven}>
                  {children}
                </tr>
              );
            },
            th: ({ children }) => <th style={s.tableHeadCell}>{children}</th>,
            td: ({ children }) => <td style={s.tableCell}>{children}</td>,
            code: ({ className, children }) => {
              const language = className?.replace(/^language-/, '') ?? '';
              const code = String(children).replace(/\n$/, '');
              const isBlock = Boolean(className?.startsWith('language-')) || code.includes('\n');

              if (!isBlock) {
                return (
                  <code style={s.inlineCode}>
                    {children}
                  </code>
                );
              }

              return (
                <div style={s.codeWrap}>
                  <button
                    type="button"
                    style={s.copyBtn}
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(code);
                      } catch {
                        toast.error('Failed to copy code');
                      }
                    }}
                    >
                      Copy
                    </button>
                  <span style={s.codeLanguage}>{language || 'code'}</span>
                  <pre style={s.codeBlock}>
                    <code data-language={language}>{code}</code>
                  </pre>
                </div>
              );
            },
            pre: ({ children }) => <>{children}</>,
          }}
        >
          {content}
        </ReactMarkdown>
      </div>
      {loading && content && (
        <span
          style={{
            width: '8px',
            height: '16px',
            borderRadius: '2px',
            background: 'rgba(88, 166, 255, 0.6)',
            display: 'inline-block',
            animation: 'unweaver-cursor-blink 1s step-end infinite',
          }}
        />
      )}
    </div>
  );
}

export default function AnalystChat({ sample }: AnalystChatProps) {
  const toast = useToast();
  const [state, setState] = useState<ChatState>('closed');
  const [messages, setMessages] = useState<AnalystChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [providerMeta, setProviderMeta] = useState<ProviderMeta | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);
  const activeSampleIdRef = useRef<string | null>(sample?.id ?? null);
  const requestSerialRef = useRef(0);
  const isWorkspaceSample = sample?.language === 'workspace';

  const scrollToBottom = useCallback(() => {
    if (!scrollRef.current) return;
    scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading, scrollToBottom]);

  useEffect(() => {
    activeSampleIdRef.current = sample?.id ?? null;
    requestSerialRef.current += 1;
    if (!sample) {
      setState('closed');
      setMessages([]);
      setInput('');
      setLoading(false);
      setProviderMeta(null);
      return;
    }
    setMessages([]);
    setInput('');
    setLoading(false);
    setProviderMeta(null);
  }, [sample?.id]);

  useEffect(() => {
    if (state !== 'closed') {
      inputRef.current?.focus();
    }
  }, [state]);

  const submit = useCallback(async (prompt?: string) => {
    if (!sample || loading) return;
    const content = (prompt ?? input).trim();
    if (!content) return;
    const sampleId = sample.id;
    const requestId = requestSerialRef.current + 1;
    requestSerialRef.current = requestId;

    const userMessage: AnalystChatMessage = { role: 'user', content };
    const pendingMessages = [...messages, userMessage];
    const withPlaceholder: AnalystChatMessage[] = [
      ...pendingMessages,
      { role: 'assistant', content: '' },
    ];

    setMessages(withPlaceholder);
    setInput('');
    setLoading(true);

    try {
      const response = await api.chatWithSample(sampleId, pendingMessages);
      if (requestSerialRef.current !== requestId || activeSampleIdRef.current !== sampleId) {
        return;
      }
      const cleaned = sanitizeAssistantText(response.answer);
      setProviderMeta({
        provider: response.provider_name,
        model: response.model_name,
        contextTruncated: response.context_truncated,
        workspaceSearchEnabled: response.workspace_search_enabled,
        workspaceFileCount: response.workspace_file_count,
        retrievedFiles: response.retrieved_files ?? [],
      });
      setMessages([
        ...pendingMessages,
        { role: 'assistant', content: cleaned || 'No final answer was returned.' },
      ]);
    } catch (err) {
      if (requestSerialRef.current !== requestId || activeSampleIdRef.current !== sampleId) {
        return;
      }
      const message = err instanceof Error ? err.message : 'Analyst chat failed';
      toast.error(message);
      setMessages([
        ...pendingMessages,
        {
          role: 'assistant',
          content: 'The analyst chat request failed. Check the active provider configuration and try again.',
        },
      ]);
    } finally {
      if (requestSerialRef.current === requestId && activeSampleIdRef.current === sampleId) {
        setLoading(false);
      }
    }
  }, [input, loading, messages, sample, toast]);

  const canSend = useMemo(
    () => Boolean(sample && input.trim() && !loading),
    [input, loading, sample],
  );

  if (!sample) return null;

  if (state === 'closed') {
    return (
      <button
        type="button"
        style={s.launcher}
        onClick={() => setState('compact')}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'scale(1.05)';
          e.currentTarget.style.boxShadow = '0 22px 42px rgba(88, 166, 255, 0.38)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'scale(1)';
          e.currentTarget.style.boxShadow = '0 18px 36px rgba(88, 166, 255, 0.28)';
        }}
      >
        <MessageSquare size={18} />
        Ask AI
      </button>
    );
  }

  const isExpanded = state === 'expanded';

  return (
    <div
      style={{
        ...s.panel,
        ...(isExpanded ? s.panelExpanded : s.panelCompact),
      }}
    >
      <div style={s.header}>
        <div style={s.headerLeft}>
          <div style={s.headerIcon}>
            <Bot size={16} />
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={s.headerTitle}>Deobfuscation Assistant</div>
            <div style={s.headerSubtitle}>
              Viewing: {sample.filename}
            </div>
          </div>
        </div>
        <div style={s.headerControls}>
          <button
            type="button"
            style={s.iconBtn}
            title={isExpanded ? 'Minimize' : 'Expand'}
            onClick={() => setState(isExpanded ? 'compact' : 'expanded')}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = 'var(--bg-hover)';
              e.currentTarget.style.color = 'var(--text-secondary)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent';
              e.currentTarget.style.color = 'var(--text-muted)';
            }}
          >
            {isExpanded ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
          </button>
          <button
            type="button"
            style={s.iconBtn}
            title="Close"
            onClick={() => setState('closed')}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = 'var(--bg-hover)';
              e.currentTarget.style.color = 'var(--text-secondary)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent';
              e.currentTarget.style.color = 'var(--text-muted)';
            }}
          >
            <X size={16} />
          </button>
        </div>
      </div>

      <div ref={scrollRef} style={s.messages}>
        {messages.length === 0 && (
          <div style={s.emptyState}>
            <div style={s.emptyIcon}>
              <Brain size={24} />
            </div>
            <div>
              <div style={s.emptyTitle}>Deobfuscation Assistant</div>
              <div style={s.emptyText}>
                Ask about original vs recovered code, suspicious behavior, unresolved layers,
                or how confident the recovery should be. The assistant can see the current
                sample context{isWorkspaceSample ? ' and search the indexed workspace files for relevant paths and excerpts.' : '.'}
              </div>
            </div>
            <div style={s.promptList}>
              {QUICK_PROMPTS.map((prompt) => (
                <button
                  key={prompt}
                  type="button"
                  style={s.promptChip}
                  onClick={() => void submit(prompt)}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = 'var(--bg-hover)';
                    e.currentTarget.style.color = 'var(--text-secondary)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = 'var(--bg-secondary)';
                    e.currentTarget.style.color = 'var(--text-muted)';
                  }}
                >
                  {prompt}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((message, index) => {
          const isAssistant = message.role === 'assistant';
          const isLoadingBubble = loading && index === messages.length - 1 && isAssistant;
          return (
            <div
              key={`${message.role}-${index}`}
              style={{
                ...s.row,
                ...(isAssistant ? s.rowAssistant : s.rowUser),
              }}
            >
              {isAssistant && (
                <div style={{ ...s.bubbleIcon, ...s.assistantIcon }}>
                  <Bot size={14} />
                </div>
              )}

              <div
                style={{
                  ...s.bubble,
                  ...(isAssistant ? s.assistantBubble : s.userBubble),
                }}
              >
                {isAssistant ? (
                  <AssistantMessage content={message.content} loading={isLoadingBubble} />
                ) : (
                  <div style={s.textBlock}>{message.content}</div>
                )}
              </div>

              {!isAssistant && (
                <div style={{ ...s.bubbleIcon, ...s.userIcon }}>
                  <User size={14} />
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div style={s.composerShell}>
        {providerMeta?.workspaceSearchEnabled && (
          <div style={s.contextStrip}>
            <div style={s.contextMeta}>
              {providerMeta.retrievedFiles.length > 0
                ? `Workspace retrieval used ${providerMeta.retrievedFiles.length} file${providerMeta.retrievedFiles.length === 1 ? '' : 's'} from ${providerMeta.workspaceFileCount} indexed workspace file${providerMeta.workspaceFileCount === 1 ? '' : 's'}.`
                : `Workspace search indexed ${providerMeta.workspaceFileCount} file${providerMeta.workspaceFileCount === 1 ? '' : 's'} for the latest answer.`}
            </div>
            {providerMeta.retrievedFiles.length > 0 && (
              <div style={s.contextChipList}>
                {providerMeta.retrievedFiles.map((file) => (
                  <span
                    key={`${file.source}:${file.path}`}
                    style={s.contextChip}
                    title={`${file.path} · ${formatRetrievedSource(file.source)}${file.line_ranges.length ? ` · ${file.line_ranges.join(', ')}` : ''}`}
                  >
                    {file.path} · {formatRetrievedSource(file.source)}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
        <div style={s.composerRow}>
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                if (canSend) void submit();
              }
            }}
            onInput={(e) => {
              const target = e.currentTarget;
              target.style.height = 'auto';
              target.style.height = `${Math.min(target.scrollHeight, 120)}px`;
            }}
            placeholder="Ask about the deobfuscation results..."
            rows={1}
            style={s.textarea}
          />
          <button
            type="button"
            disabled={!canSend}
            onClick={() => void submit()}
            style={{
              ...s.sendBtn,
              opacity: canSend ? 1 : 0.3,
              cursor: canSend ? 'pointer' : 'not-allowed',
            }}
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
          </button>
        </div>
        <div style={s.footer}>
          <span>{providerMeta ? `${providerMeta.provider} · ${providerMeta.model}` : 'Uses the configured analysis provider'}</span>
          <span>{providerMeta?.contextTruncated ? 'Context trimmed to fit the model window.' : 'Thinking tokens are hidden.'}</span>
        </div>
      </div>
    </div>
  );
}
