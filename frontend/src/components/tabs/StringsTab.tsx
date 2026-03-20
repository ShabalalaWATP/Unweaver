import { useState, useMemo, useCallback } from 'react';
import { Copy, Search, ArrowUpDown, ClipboardCopy, Regex } from 'lucide-react';
import type { StringEntry } from '@/types';
import { useAsync } from '@/hooks/useApi';
import { useToast } from '@/components/common/Toast';
import * as api from '@/services/api';
import { truncate } from '@/utils/format';

interface StringsTabProps {
  sampleId: string;
}

type SortKey = 'value' | 'encoding' | 'decoded' | 'context';
type SortDir = 'asc' | 'desc';

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
  count: {
    fontSize: '11px',
    color: 'var(--text-muted)',
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
  tableWrap: {
    flex: 1,
    overflow: 'auto',
  } as React.CSSProperties,
  th: {
    cursor: 'pointer',
    userSelect: 'none',
    position: 'sticky',
    top: 0,
    background: 'var(--bg-secondary)',
    zIndex: 1,
  } as React.CSSProperties,
  mono: {
    fontFamily: 'var(--font-mono)',
    fontSize: '11px',
    wordBreak: 'break-all',
  } as React.CSSProperties,
  copyBtn: {
    padding: '2px',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'inline-flex',
    alignItems: 'center',
    transition: 'color 0.1s',
    flexShrink: 0,
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

export default function StringsTab({ sampleId }: StringsTabProps) {
  const { data: strings, loading } = useAsync<StringEntry[]>(
    () => api.getStrings(sampleId),
    [sampleId],
  );
  const [filter, setFilter] = useState('');
  const [useRegex, setUseRegex] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>('value');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const toast = useToast();

  const handleSort = useCallback(
    (key: SortKey) => {
      if (sortKey === key) {
        setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
      } else {
        setSortKey(key);
        setSortDir('asc');
      }
    },
    [sortKey],
  );

  const { filtered, regexError } = useMemo(() => {
    if (!strings) return { filtered: [], regexError: null };
    let result = strings;
    let regexErr: string | null = null;

    if (filter) {
      if (useRegex) {
        try {
          const re = new RegExp(filter, 'i');
          result = result.filter(
            (entry) =>
              re.test(entry.value) ||
              (entry.decoded && re.test(entry.decoded)) ||
              (entry.context && re.test(entry.context)),
          );
        } catch (e) {
          regexErr = e instanceof Error ? e.message : 'Invalid regex';
        }
      } else {
        const lower = filter.toLowerCase();
        result = result.filter(
          (entry) =>
            entry.value.toLowerCase().includes(lower) ||
            (entry.decoded && entry.decoded.toLowerCase().includes(lower)) ||
            (entry.context && entry.context.toLowerCase().includes(lower)),
        );
      }
    }
    result = [...result].sort((a, b) => {
      const aVal = (a[sortKey] ?? '') as string;
      const bVal = (b[sortKey] ?? '') as string;
      const cmp = aVal.localeCompare(bVal);
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return { filtered: result, regexError: regexErr };
  }, [strings, filter, useRegex, sortKey, sortDir]);

  const copyToClipboard = useCallback((text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  }, [toast]);

  const copyAll = useCallback(() => {
    const text = filtered.map((e) => e.decoded ?? e.value).join('\n');
    navigator.clipboard.writeText(text);
    toast.success(`Copied ${filtered.length} strings`);
  }, [filtered, toast]);

  if (loading) {
    return <div style={s.emptyState}>Loading strings...</div>;
  }

  if (!strings || strings.length === 0) {
    return <div style={s.emptyState}>No strings extracted</div>;
  }

  const renderSortIcon = (key: SortKey) =>
    sortKey === key ? (
      <ArrowUpDown size={10} style={{ opacity: 0.8 }} />
    ) : (
      <ArrowUpDown size={10} style={{ opacity: 0.3 }} />
    );

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
            placeholder={useRegex ? 'Regex filter...' : 'Filter strings...'}
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
          style={s.copyAllBtn}
          onClick={copyAll}
          title="Copy all filtered strings"
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
          {filtered.length} / {strings.length}
        </span>
        {regexError && <span style={s.regexError}>{regexError}</span>}
      </div>
      <div style={s.tableWrap}>
        <table>
          <thead>
            <tr>
              <th style={s.th} onClick={() => handleSort('value')}>
                Value {renderSortIcon('value')}
              </th>
              <th style={s.th} onClick={() => handleSort('encoding')}>
                Encoding {renderSortIcon('encoding')}
              </th>
              <th style={s.th} onClick={() => handleSort('decoded')}>
                Decoded {renderSortIcon('decoded')}
              </th>
              <th style={s.th} onClick={() => handleSort('context')}>
                Context {renderSortIcon('context')}
              </th>
              <th style={{ ...s.th, width: 32 }} />
            </tr>
          </thead>
          <tbody>
            {filtered.map((entry, i) => (
              <tr key={i}>
                <td style={s.mono} title={entry.value}>
                  {truncate(entry.value, 80)}
                </td>
                <td style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {entry.encoding ?? '-'}
                </td>
                <td style={s.mono} title={entry.decoded ?? undefined}>
                  {entry.decoded ? truncate(entry.decoded, 60) : '-'}
                </td>
                <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  {entry.context ? truncate(entry.context, 40) : '-'}
                </td>
                <td>
                  <button
                    style={s.copyBtn}
                    onClick={() => copyToClipboard(entry.decoded ?? entry.value)}
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
