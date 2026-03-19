import { useState, useCallback } from 'react';
import { ChevronDown, ChevronRight, CheckCircle, XCircle, RotateCcw, TrendingUp, TrendingDown } from 'lucide-react';
import type { TransformRecord, AnalysisState } from '@/types';
import { useAsync } from '@/hooks/useApi';
import * as api from '@/services/api';

interface TransformHistoryTabProps {
  sampleId: string;
  analysisState: AnalysisState | null;
}

const s = {
  root: {
    height: '100%',
    overflow: 'auto',
    padding: '16px',
  } as React.CSSProperties,
  timeline: {
    position: 'relative',
    paddingLeft: '24px',
  } as React.CSSProperties,
  line: {
    position: 'absolute',
    left: '7px',
    top: '0',
    bottom: '0',
    width: '2px',
    background: 'var(--border)',
  } as React.CSSProperties,
  entry: {
    position: 'relative',
    marginBottom: '12px',
  } as React.CSSProperties,
  dot: {
    position: 'absolute',
    left: '-21px',
    top: '8px',
    width: '12px',
    height: '12px',
    borderRadius: '50%',
    border: '2px solid var(--bg-primary)',
    zIndex: 1,
  } as React.CSSProperties,
  card: {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    overflow: 'hidden',
  } as React.CSSProperties,
  cardHeader: {
    padding: '8px 12px',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    cursor: 'pointer',
    userSelect: 'none',
    transition: 'background 0.1s',
  } as React.CSSProperties,
  iteration: {
    fontSize: '10px',
    fontWeight: 700,
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-muted)',
    minWidth: '28px',
  } as React.CSSProperties,
  actionName: {
    fontSize: '12px',
    fontWeight: 600,
    color: 'var(--text-primary)',
    flex: 1,
  } as React.CSSProperties,
  reason: {
    fontSize: '11px',
    color: 'var(--text-secondary)',
    padding: '0 12px 8px 12px',
  } as React.CSSProperties,
  badges: {
    display: 'flex',
    gap: '6px',
    alignItems: 'center',
  } as React.CSSProperties,
  badge: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '3px',
    padding: '1px 6px',
    borderRadius: 'var(--radius-sm)',
    fontSize: '10px',
    fontWeight: 500,
  } as React.CSSProperties,
  details: {
    padding: '8px 12px',
    borderTop: '1px solid var(--border)',
    background: 'var(--bg-primary)',
  } as React.CSSProperties,
  detailRow: {
    display: 'flex',
    gap: '16px',
    marginBottom: '6px',
  } as React.CSSProperties,
  detailLabel: {
    fontSize: '10px',
    fontWeight: 600,
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    minWidth: '60px',
  } as React.CSSProperties,
  detailValue: {
    fontSize: '11px',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-secondary)',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
  } as React.CSSProperties,
  metric: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '3px',
    fontSize: '10px',
    fontFamily: 'var(--font-mono)',
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

function MetricChange({ before, after, label }: { before: number; after: number; label: string }) {
  const delta = after - before;
  const improved = delta > 0;
  const color = improved ? 'var(--success)' : delta < 0 ? 'var(--danger)' : 'var(--text-muted)';
  const Icon = improved ? TrendingUp : TrendingDown;

  return (
    <span style={{ ...s.metric, color }}>
      {delta !== 0 && <Icon size={10} />}
      {label}: {Math.round(before * 100)}% → {Math.round(after * 100)}%
      {delta !== 0 && ` (${improved ? '+' : ''}${Math.round(delta * 100)}%)`}
    </span>
  );
}

export default function TransformHistoryTab({ sampleId, analysisState }: TransformHistoryTabProps) {
  const { data: fetchedTransforms, loading } = useAsync<TransformRecord[]>(
    () => api.getTransforms(sampleId),
    [sampleId],
  );
  const [expandedSet, setExpandedSet] = useState<Set<number>>(new Set());

  const transforms = fetchedTransforms ?? analysisState?.transform_history ?? [];

  const toggleExpand = useCallback((iteration: number) => {
    setExpandedSet((prev) => {
      const next = new Set(prev);
      if (next.has(iteration)) {
        next.delete(iteration);
      } else {
        next.add(iteration);
      }
      return next;
    });
  }, []);

  if (loading) {
    return <div style={s.emptyState}>Loading transform history...</div>;
  }

  if (transforms.length === 0) {
    return <div style={s.emptyState}>No transforms applied yet</div>;
  }

  return (
    <div style={s.root}>
      <div style={s.timeline as React.CSSProperties}>
        <div style={s.line as React.CSSProperties} />
        {transforms.map((t) => {
          const expanded = expandedSet.has(t.iteration);
          return (
            <div key={t.iteration} style={s.entry as React.CSSProperties}>
              <div
                style={{
                  ...(s.dot as React.CSSProperties),
                  background: t.success
                    ? t.retry_revert
                      ? 'var(--warning)'
                      : 'var(--success)'
                    : 'var(--danger)',
                }}
              />
              <div style={s.card}>
                <div
                  style={s.cardHeader}
                  onClick={() => toggleExpand(t.iteration)}
                  onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--bg-tertiary)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                >
                  {expanded ? (
                    <ChevronDown size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                  ) : (
                    <ChevronRight size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                  )}
                  <span style={s.iteration}>#{t.iteration}</span>
                  <span style={s.actionName}>{t.action}</span>
                  <div style={s.badges}>
                    {t.success ? (
                      <span
                        style={{
                          ...s.badge,
                          color: 'var(--success)',
                          background: 'var(--success-muted)',
                        }}
                      >
                        <CheckCircle size={10} />
                        OK
                      </span>
                    ) : (
                      <span
                        style={{
                          ...s.badge,
                          color: 'var(--danger)',
                          background: 'var(--danger-muted)',
                        }}
                      >
                        <XCircle size={10} />
                        Fail
                      </span>
                    )}
                    {t.retry_revert && (
                      <span
                        style={{
                          ...s.badge,
                          color: 'var(--warning)',
                          background: 'var(--warning-muted)',
                        }}
                      >
                        <RotateCcw size={10} />
                        Reverted
                      </span>
                    )}
                  </div>
                </div>
                {t.reason && <div style={s.reason}>{t.reason}</div>}
                {!expanded && (
                  <div style={{ padding: '0 12px 8px', display: 'flex', gap: '16px' }}>
                    <MetricChange
                      before={t.confidence_before}
                      after={t.confidence_after}
                      label="Conf"
                    />
                    <MetricChange
                      before={t.readability_before}
                      after={t.readability_after}
                      label="Read"
                    />
                  </div>
                )}
                {expanded && (
                  <div style={s.details}>
                    <div style={s.detailRow}>
                      <span style={s.detailLabel}>Conf.</span>
                      <MetricChange
                        before={t.confidence_before}
                        after={t.confidence_after}
                        label="Confidence"
                      />
                    </div>
                    <div style={s.detailRow}>
                      <span style={s.detailLabel}>Read.</span>
                      <MetricChange
                        before={t.readability_before}
                        after={t.readability_after}
                        label="Readability"
                      />
                    </div>
                    {Object.keys(t.inputs).length > 0 && (
                      <div style={s.detailRow}>
                        <span style={s.detailLabel}>Inputs</span>
                        <span style={s.detailValue}>
                          {JSON.stringify(t.inputs, null, 2)}
                        </span>
                      </div>
                    )}
                    {Object.keys(t.outputs).length > 0 && (
                      <div style={s.detailRow}>
                        <span style={s.detailLabel}>Outputs</span>
                        <span style={s.detailValue}>
                          {JSON.stringify(t.outputs, null, 2)}
                        </span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
