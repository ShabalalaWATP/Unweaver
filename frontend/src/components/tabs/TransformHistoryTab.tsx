import { useState, useCallback } from 'react';
import { ChevronDown, ChevronRight, CheckCircle, XCircle, RotateCcw, TrendingUp, TrendingDown, Code2, X, Loader2 } from 'lucide-react';
import type { TransformRecord, AnalysisState } from '@/types';
import { useAsync } from '@/hooks/useApi';
import * as api from '@/services/api';
import type { IterationSnapshot } from '@/services/api';
import CodeViewer from '@/components/editors/CodeViewer';

interface TransformHistoryTabProps {
  sampleId: string;
  analysisState: AnalysisState | null;
}

const s = {
  root: {
    height: '100%',
    display: 'flex',
    overflow: 'hidden',
  } as React.CSSProperties,
  timelinePane: {
    flex: 1,
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
    borderRadius: 'var(--radius-lg, 10px)',
    overflow: 'hidden',
    transition: 'border-color 0.15s ease',
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
  viewCodeBtn: {
    padding: '2px 8px',
    borderRadius: 'var(--radius-sm)',
    fontSize: '10px',
    fontWeight: 500,
    color: 'var(--accent)',
    background: 'var(--accent-muted)',
    border: '1px solid var(--accent-border)',
    cursor: 'pointer',
    display: 'inline-flex',
    alignItems: 'center',
    gap: '3px',
    transition: 'all 0.15s',
    flexShrink: 0,
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
  // Code viewer panel
  codePanel: {
    width: '50%',
    borderLeft: '1px solid var(--border)',
    display: 'flex',
    flexDirection: 'column',
    background: 'var(--bg-primary)',
    animation: 'unweaver-fade-in 0.2s ease',
  } as React.CSSProperties,
  codePanelHeader: {
    padding: '8px 12px',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    background: 'var(--bg-secondary)',
    flexShrink: 0,
  } as React.CSSProperties,
  codePanelTitle: {
    fontSize: '11px',
    fontWeight: 600,
    color: 'var(--text-primary)',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  } as React.CSSProperties,
  codePanelClose: {
    padding: '3px',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    transition: 'color 0.15s',
  } as React.CSSProperties,
  codePanelBody: {
    flex: 1,
    overflow: 'hidden',
  } as React.CSSProperties,
  loadingCode: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100%',
    color: 'var(--text-muted)',
    fontSize: '12px',
    gap: '8px',
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
  const [viewingIteration, setViewingIteration] = useState<number | null>(null);
  const [iterationCode, setIterationCode] = useState<string | null>(null);
  const [loadingCode, setLoadingCode] = useState(false);
  const [iterationSnapshots, setIterationSnapshots] = useState<IterationSnapshot[] | null>(null);

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

  // Fetch iteration snapshots once when component mounts (lazy)
  const fetchSnapshots = useCallback(async () => {
    if (iterationSnapshots !== null) return iterationSnapshots;
    try {
      const snapshots = await api.getIterations(sampleId);
      setIterationSnapshots(snapshots);
      return snapshots;
    } catch {
      setIterationSnapshots([]);
      return [];
    }
  }, [sampleId, iterationSnapshots]);

  const handleViewCode = useCallback(async (iteration: number) => {
    if (viewingIteration === iteration) {
      setViewingIteration(null);
      return;
    }

    setViewingIteration(iteration);
    setLoadingCode(true);
    setIterationCode(null);

    try {
      const snapshots = await fetchSnapshots();
      // Find the snapshot matching this iteration
      const snap = snapshots.find((s) => s.iteration_number === iteration);
      if (snap?.state_json) {
        // Look for recovered code in the state
        const state = snap.state_json as unknown as Record<string, unknown>;
        const code = (state['current_code'] as string | undefined)
          ?? (state['recovered_code'] as string | undefined)
          ?? null;
        if (code) {
          setIterationCode(code);
        } else {
          // Try to reconstruct from analysis_summary or transform outputs
          setIterationCode(`// Iteration ${iteration} state snapshot\n// No recovered code captured at this iteration.\n\n${JSON.stringify(state, null, 2)}`);
        }
      } else {
        setIterationCode(`// No snapshot available for iteration ${iteration}`);
      }
    } catch {
      setIterationCode(`// Failed to load snapshot for iteration ${iteration}`);
    } finally {
      setLoadingCode(false);
    }
  }, [viewingIteration, fetchSnapshots]);

  if (loading) {
    return <div style={s.emptyState}>Loading transform history...</div>;
  }

  if (transforms.length === 0) {
    return <div style={s.emptyState}>No transforms applied yet</div>;
  }

  return (
    <div style={s.root}>
      <div style={{
        ...s.timelinePane,
        ...(viewingIteration !== null ? { flex: '0 0 50%' } : {}),
      }}>
        <div style={s.timeline as React.CSSProperties}>
          <div style={s.line as React.CSSProperties} />
          {transforms.map((t) => {
            const expanded = expandedSet.has(t.iteration);
            const isViewing = viewingIteration === t.iteration;
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
                <div style={{
                  ...s.card,
                  ...(isViewing ? { borderColor: 'var(--accent)' } : {}),
                }}>
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
                    <button
                      style={{
                        ...s.viewCodeBtn,
                        ...(isViewing ? { background: 'var(--accent)', color: 'white', borderColor: 'var(--accent)' } : {}),
                      }}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleViewCode(t.iteration);
                      }}
                      onMouseEnter={(e) => {
                        if (!isViewing) {
                          e.currentTarget.style.background = 'var(--accent-hover-bg)';
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (!isViewing) {
                          e.currentTarget.style.background = 'var(--accent-muted)';
                        }
                      }}
                    >
                      <Code2 size={10} />
                      Code
                    </button>
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

      {/* Code viewer panel */}
      {viewingIteration !== null && (
        <div style={s.codePanel as React.CSSProperties}>
          <div style={s.codePanelHeader}>
            <span style={s.codePanelTitle}>
              <Code2 size={12} style={{ opacity: 0.6 }} />
              Code at iteration #{viewingIteration}
            </span>
            <button
              style={s.codePanelClose}
              onClick={() => setViewingIteration(null)}
              onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--text-primary)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-muted)'; }}
            >
              <X size={14} />
            </button>
          </div>
          <div style={s.codePanelBody as React.CSSProperties}>
            {loadingCode ? (
              <div style={s.loadingCode}>
                <Loader2 size={14} style={{ animation: 'unweaver-spin 1s linear infinite' }} />
                Loading snapshot...
              </div>
            ) : iterationCode ? (
              <CodeViewer
                value={iterationCode}
                language={analysisState?.language}
                readOnly={true}
              />
            ) : (
              <div style={s.loadingCode}>No code available</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
