import { useState, useMemo, useCallback } from 'react';
import { Copy, Search, ArrowUpDown } from 'lucide-react';
import type { StringEntry } from '@/types';
import { useAsync } from '@/hooks/useApi';
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
};

export default function StringsTab({ sampleId }: StringsTabProps) {
  const { data: strings, loading } = useAsync<StringEntry[]>(
    () => api.getStrings(sampleId),
    [sampleId],
  );
  const [filter, setFilter] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('value');
  const [sortDir, setSortDir] = useState<SortDir>('asc');

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

  const filtered = useMemo(() => {
    if (!strings) return [];
    let result = strings;
    if (filter) {
      const lower = filter.toLowerCase();
      result = result.filter(
        (s) =>
          s.value.toLowerCase().includes(lower) ||
          (s.decoded && s.decoded.toLowerCase().includes(lower)) ||
          (s.context && s.context.toLowerCase().includes(lower)),
      );
    }
    result = [...result].sort((a, b) => {
      const aVal = (a[sortKey] ?? '') as string;
      const bVal = (b[sortKey] ?? '') as string;
      const cmp = aVal.localeCompare(bVal);
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return result;
  }, [strings, filter, sortKey, sortDir]);

  const copyToClipboard = useCallback((text: string) => {
    navigator.clipboard.writeText(text);
  }, []);

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
        <div style={s.searchWrap}>
          <Search size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
          <input
            style={s.searchInput}
            placeholder="Filter strings..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <span style={s.count}>
          {filtered.length} / {strings.length}
        </span>
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
