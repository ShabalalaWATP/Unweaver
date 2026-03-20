import { useState, useMemo, useCallback } from 'react';
import { Copy, Search, Shield, ClipboardCopy, Regex } from 'lucide-react';
import type { IOC, IOCType } from '@/types';
import { useAsync } from '@/hooks/useApi';
import { useToast } from '@/components/common/Toast';
import * as api from '@/services/api';
import { defangIOC, truncate } from '@/utils/format';

interface IOCsTabProps {
  sampleId: string;
}

const TYPE_COLORS: Record<IOCType, string> = {
  ip: 'var(--ioc-ip)',
  domain: 'var(--ioc-domain)',
  url: 'var(--ioc-url)',
  hash: 'var(--ioc-hash)',
  email: 'var(--ioc-email)',
  filepath: 'var(--ioc-filepath)',
  registry: 'var(--ioc-registry)',
  mutex: 'var(--ioc-mutex)',
  other: 'var(--ioc-other)',
};

const s = {
  root: {
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  } as React.CSSProperties,
  toolbar: {
    padding: '8px 12px',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    background: 'var(--bg-secondary)',
    flexShrink: 0,
  } as React.CSSProperties,
  searchWrap: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    flex: 1,
    maxWidth: 300,
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    padding: '4px 8px',
  } as React.CSSProperties,
  searchInput: {
    border: 'none',
    background: 'transparent',
    color: 'var(--text-primary)',
    fontSize: '12px',
    outline: 'none',
    flex: 1,
    padding: 0,
  } as React.CSSProperties,
  toggleBtn: {
    padding: '3px 8px',
    fontSize: '10px',
    fontWeight: 500,
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border)',
    cursor: 'pointer',
    transition: 'all 0.15s',
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  } as React.CSSProperties,
  defangToggle: {
    padding: '3px 8px',
    fontSize: '10px',
    fontWeight: 500,
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border)',
    cursor: 'pointer',
    transition: 'all 0.15s',
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  } as React.CSSProperties,
  copyAllBtn: {
    padding: '3px 8px',
    fontSize: '10px',
    fontWeight: 500,
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    transition: 'all 0.15s',
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  } as React.CSSProperties,
  count: {
    fontSize: '11px',
    color: 'var(--text-muted)',
  } as React.CSSProperties,
  tableWrap: {
    flex: 1,
    overflow: 'auto',
  } as React.CSSProperties,
  th: {
    position: 'sticky',
    top: 0,
    background: 'var(--bg-secondary)',
    zIndex: 1,
  } as React.CSSProperties,
  typeBadge: {
    display: 'inline-block',
    padding: '1px 6px',
    borderRadius: 'var(--radius-sm)',
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
  } as React.CSSProperties,
  mono: {
    fontFamily: 'var(--font-mono)',
    fontSize: '11px',
    wordBreak: 'break-all',
  } as React.CSSProperties,
  confidenceBar: {
    width: 50,
    height: 4,
    borderRadius: 2,
    background: 'var(--bg-tertiary)',
    overflow: 'hidden',
    display: 'inline-block',
    verticalAlign: 'middle',
    marginRight: 6,
  } as React.CSSProperties,
  copyBtn: {
    padding: '2px',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'inline-flex',
    alignItems: 'center',
    transition: 'color 0.1s',
  } as React.CSSProperties,
  emptyState: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100%',
    color: 'var(--text-muted)',
    fontSize: '13px',
  } as React.CSSProperties,
  regexError: {
    fontSize: '10px',
    color: 'var(--danger)',
    padding: '0 4px',
  } as React.CSSProperties,
};

function getConfidenceColor(val: number): string {
  if (val >= 0.7) return 'var(--success)';
  if (val >= 0.4) return 'var(--warning)';
  return 'var(--danger)';
}

export default function IOCsTab({ sampleId }: IOCsTabProps) {
  const { data: iocs, loading } = useAsync<IOC[]>(
    () => api.getIOCs(sampleId),
    [sampleId],
  );
  const [filter, setFilter] = useState('');
  const [useRegex, setUseRegex] = useState(false);
  const [defanged, setDefanged] = useState(true);
  const toast = useToast();

  const { filtered, regexError } = useMemo(() => {
    if (!iocs) return { filtered: [], regexError: null };
    let result = iocs;
    let regexErr: string | null = null;

    if (filter) {
      if (useRegex) {
        try {
          const re = new RegExp(filter, 'i');
          result = result.filter(
            (ioc) =>
              re.test(ioc.value) ||
              re.test(ioc.type) ||
              (ioc.context && re.test(ioc.context)),
          );
        } catch (e) {
          regexErr = e instanceof Error ? e.message : 'Invalid regex';
        }
      } else {
        const lower = filter.toLowerCase();
        result = result.filter(
          (ioc) =>
            ioc.value.toLowerCase().includes(lower) ||
            ioc.type.toLowerCase().includes(lower) ||
            (ioc.context && ioc.context.toLowerCase().includes(lower)),
        );
      }
    }
    return { filtered: result, regexError: regexErr };
  }, [iocs, filter, useRegex]);

  const copyToClipboard = useCallback(
    (ioc: IOC) => {
      const text = defanged ? defangIOC(ioc.value, ioc.type) : ioc.value;
      navigator.clipboard.writeText(text);
      toast.success('IOC copied to clipboard');
    },
    [defanged, toast],
  );

  const copyAll = useCallback(() => {
    const text = filtered
      .map((ioc) => (defanged ? defangIOC(ioc.value, ioc.type) : ioc.value))
      .join('\n');
    navigator.clipboard.writeText(text);
    toast.success(`Copied ${filtered.length} IOCs`);
  }, [filtered, defanged, toast]);

  if (loading) {
    return <div style={s.emptyState}>Loading IOCs...</div>;
  }

  if (!iocs || iocs.length === 0) {
    return <div style={s.emptyState}>No IOCs extracted</div>;
  }

  return (
    <div style={s.root}>
      <div style={s.toolbar}>
        <div style={{
          ...s.searchWrap,
          ...(regexError ? { borderColor: 'var(--danger)' } : {}),
        }}>
          <Search size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
          <input
            style={s.searchInput}
            placeholder={useRegex ? 'Regex filter...' : 'Filter IOCs...'}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <button
          style={{
            ...s.toggleBtn,
            background: useRegex ? 'var(--accent-muted)' : 'var(--bg-tertiary)',
            color: useRegex ? 'var(--accent)' : 'var(--text-secondary)',
            borderColor: useRegex ? 'var(--accent)' : 'var(--border)',
          }}
          onClick={() => setUseRegex(!useRegex)}
          title="Toggle regex search"
        >
          <Regex size={10} />
          Regex
        </button>
        <button
          style={{
            ...s.defangToggle,
            background: defanged ? 'var(--accent-muted)' : 'var(--bg-tertiary)',
            color: defanged ? 'var(--accent)' : 'var(--text-secondary)',
            borderColor: defanged ? 'var(--accent)' : 'var(--border)',
          }}
          onClick={() => setDefanged(!defanged)}
        >
          <Shield size={10} />
          {defanged ? 'Defanged' : 'Raw'}
        </button>
        <button
          style={s.copyAllBtn}
          onClick={copyAll}
          title="Copy all filtered IOCs"
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = 'var(--accent)';
            e.currentTarget.style.color = 'var(--accent)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = 'var(--border)';
            e.currentTarget.style.color = 'var(--text-secondary)';
          }}
        >
          <ClipboardCopy size={10} />
          Copy All
        </button>
        <span style={s.count}>
          {filtered.length} / {iocs.length}
        </span>
        {regexError && <span style={s.regexError}>{regexError}</span>}
      </div>
      <div style={s.tableWrap}>
        <table>
          <thead>
            <tr>
              <th style={{ ...s.th, width: 80 }}>Type</th>
              <th style={s.th}>Value</th>
              <th style={s.th}>Context</th>
              <th style={{ ...s.th, width: 100 }}>Confidence</th>
              <th style={{ ...s.th, width: 32 }} />
            </tr>
          </thead>
          <tbody>
            {filtered.map((ioc, i) => (
              <tr key={i}>
                <td>
                  <span
                    style={{
                      ...s.typeBadge,
                      color: TYPE_COLORS[ioc.type] ?? TYPE_COLORS.other,
                      background: `${TYPE_COLORS[ioc.type] ?? TYPE_COLORS.other}18`,
                    }}
                  >
                    {ioc.type}
                  </span>
                </td>
                <td style={s.mono} title={ioc.value}>
                  {defanged
                    ? truncate(defangIOC(ioc.value, ioc.type), 80)
                    : truncate(ioc.value, 80)}
                </td>
                <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  {ioc.context ? truncate(ioc.context, 50) : '-'}
                </td>
                <td>
                  <span style={s.confidenceBar}>
                    <span
                      style={{
                        display: 'block',
                        height: '100%',
                        width: `${ioc.confidence * 100}%`,
                        background: getConfidenceColor(ioc.confidence),
                        borderRadius: 2,
                      }}
                    />
                  </span>
                  <span style={{ fontSize: '10px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    {Math.round(ioc.confidence * 100)}%
                  </span>
                </td>
                <td>
                  <button
                    style={s.copyBtn}
                    onClick={() => copyToClipboard(ioc)}
                    title="Copy"
                    onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--text-primary)'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-muted)'; }}
                  >
                    <Copy size={12} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
