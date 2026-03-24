import { useState } from 'react';
import { ChevronDown, ChevronRight, Zap, XCircle, RotateCcw, Brain, Target, TrendingUp, TrendingDown } from 'lucide-react';
import type { AnalysisState, TransformRecord } from '@/types';

interface AgentNotebookTabProps {
  analysisState: AnalysisState | null;
}

const s = {
  root: {
    height: '100%',
    overflow: 'auto',
    padding: '16px',
  } as React.CSSProperties,
  header: {
    marginBottom: '16px',
  } as React.CSSProperties,
  headerTitle: {
    fontSize: '14px',
    fontWeight: 700,
    color: 'var(--text-primary)',
    marginBottom: '4px',
  } as React.CSSProperties,
  headerSub: {
    fontSize: '12px',
    color: 'var(--text-muted)',
    lineHeight: '1.5',
  } as React.CSSProperties,
  classificationCard: {
    background: 'linear-gradient(135deg, rgba(88,166,255,0.08), rgba(88,166,255,0.02))',
    border: '1px solid rgba(88,166,255,0.15)',
    borderRadius: 'var(--radius-lg)',
    padding: '14px',
    marginBottom: '14px',
  } as React.CSSProperties,
  plannerCard: {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: '14px',
    marginBottom: '14px',
  } as React.CSSProperties,
  cardLabel: {
    fontSize: '10px',
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    color: 'var(--accent)',
    marginBottom: '8px',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  } as React.CSSProperties,
  cardBody: {
    fontSize: '12px',
    lineHeight: '1.7',
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
  iterCard: {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    marginBottom: '10px',
    overflow: 'hidden',
  } as React.CSSProperties,
  iterHeader: {
    padding: '10px 14px',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    cursor: 'pointer',
    userSelect: 'none',
  } as React.CSSProperties,
  iterNum: {
    fontSize: '11px',
    fontWeight: 700,
    fontFamily: 'var(--font-mono)',
    color: 'var(--accent)',
    flexShrink: 0,
  } as React.CSSProperties,
  iterAction: {
    fontSize: '12px',
    fontWeight: 600,
    color: 'var(--text-primary)',
    flex: 1,
  } as React.CSSProperties,
  statusPill: {
    fontSize: '10px',
    fontWeight: 600,
    padding: '2px 8px',
    borderRadius: 'var(--radius-sm)',
    flexShrink: 0,
  } as React.CSSProperties,
  metricRow: {
    display: 'flex',
    gap: '16px',
    padding: '8px 14px',
    borderTop: '1px solid var(--border)',
    fontSize: '11px',
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
  metricItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  } as React.CSSProperties,
  reasonBlock: {
    padding: '8px 14px',
    borderTop: '1px solid var(--border)',
    fontSize: '12px',
    lineHeight: '1.6',
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
  detailBlock: {
    padding: '8px 14px',
    borderTop: '1px solid var(--border)',
    fontSize: '11px',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-muted)',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
    maxHeight: '120px',
    overflow: 'auto',
  } as React.CSSProperties,
  emptyState: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100%',
    color: 'var(--text-muted)',
    fontSize: '13px',
    flexDirection: 'column',
    gap: '6px',
  } as React.CSSProperties,
};

function formatAction(action: string): string {
  return action
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .replace(/Llm /g, 'LLM ')
    .replace(/Iocs/g, 'IOCs');
}

function describeTransform(t: TransformRecord): string {
  const action = formatAction(t.action);
  const confDelta = t.confidence_after - t.confidence_before;
  const readDelta = t.readability_after - t.readability_before;

  if (t.retry_revert) {
    return `${action} was attempted but reverted — the result reduced quality.`;
  }
  if (!t.success) {
    const desc = t.outputs?.description;
    return `${action} failed${typeof desc === 'string' ? `: ${desc}` : '. No applicable patterns found.'}`;
  }

  const parts = [`${action} succeeded`];

  if (confDelta > 0.05) parts.push(`boosting confidence by ${Math.round(confDelta * 100)}%`);
  else if (confDelta < -0.02) parts.push(`with slight confidence decrease`);

  if (readDelta > 0.05) parts.push(`improving readability by ${Math.round(readDelta * 100)}%`);

  const desc = t.outputs?.description;
  if (typeof desc === 'string' && desc.length > 5) {
    parts.push(`— ${desc}`);
  }

  return parts.join(', ') + '.';
}

function getStatusStyle(t: TransformRecord): { color: string; bg: string; label: string; icon: React.ReactNode } {
  if (t.retry_revert) return { color: 'var(--warning)', bg: 'var(--warning-muted)', label: 'REVERTED', icon: <RotateCcw size={10} /> };
  if (t.success) return { color: 'var(--success)', bg: 'var(--success-muted)', label: 'OK', icon: <Zap size={10} /> };
  return { color: 'var(--danger)', bg: 'var(--danger-muted)', label: 'FAIL', icon: <XCircle size={10} /> };
}

export default function AgentNotebookTab({ analysisState }: AgentNotebookTabProps) {
  const [expandedSet, setExpandedSet] = useState<Set<number>>(new Set());

  if (!analysisState) {
    return (
      <div style={s.emptyState}>
        <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-secondary)' }}>
          No agent log available
        </div>
        <div>Run analysis to see the decision log</div>
      </div>
    );
  }

  const transforms = analysisState.transform_history ?? [];
  const iterState = analysisState.iteration_state;
  const classification = iterState?.llm_classification;
  const plannerAnalysis = iterState?.planner_analysis as string | undefined;

  const toggle = (iter: number) => {
    setExpandedSet((prev) => {
      const next = new Set(prev);
      if (next.has(iter)) next.delete(iter);
      else next.add(iter);
      return next;
    });
  };

  const succeeded = transforms.filter((t) => t.success && !t.retry_revert).length;
  const failed = transforms.filter((t) => !t.success).length;
  const reverted = transforms.filter((t) => t.retry_revert).length;

  return (
    <div style={s.root}>
      {/* Header summary */}
      <div style={s.header}>
        <div style={s.headerTitle}>Decision Log</div>
        <div style={s.headerSub}>
          {transforms.length} transforms across {iterState?.current_iteration ?? 0} iterations
          {' — '}
          <span style={{ color: 'var(--success)' }}>{succeeded} succeeded</span>
          {failed > 0 && <>, <span style={{ color: 'var(--danger)' }}>{failed} failed</span></>}
          {reverted > 0 && <>, <span style={{ color: 'var(--warning)' }}>{reverted} reverted</span></>}
        </div>
      </div>

      {/* LLM Classification card */}
      {classification && (
        <div style={s.classificationCard}>
          <div style={s.cardLabel}>
            <Brain size={12} />
            LLM Classification (Iteration 1)
          </div>
          <div style={s.cardBody}>
            <strong>{classification.obfuscation_type}</strong>
            {classification.recommended_strategy && (
              <> — {classification.recommended_strategy}</>
            )}
            {classification.layers && classification.layers.length > 0 && (
              <div style={{ marginTop: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
                Layers: {classification.layers.join(' → ')}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Planner analysis card */}
      {plannerAnalysis && (
        <div style={s.plannerCard}>
          <div style={{ ...s.cardLabel, color: 'var(--text-muted)' }}>
            <Target size={12} />
            Planner Analysis
          </div>
          <div style={s.cardBody}>{plannerAnalysis}</div>
        </div>
      )}

      {/* Transform decision cards */}
      {transforms.length === 0 ? (
        <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>
          No iterations recorded yet
        </div>
      ) : (
        transforms.map((t) => {
          const expanded = expandedSet.has(t.iteration);
          const status = getStatusStyle(t);
          const confDelta = t.confidence_after - t.confidence_before;

          return (
            <div key={t.iteration} style={s.iterCard}>
              <div
                style={s.iterHeader}
                onClick={() => toggle(t.iteration)}
                onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--bg-tertiary)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
              >
                {expanded
                  ? <ChevronDown size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                  : <ChevronRight size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                }
                <span style={s.iterNum}>#{t.iteration}</span>
                <span style={s.iterAction}>{formatAction(t.action)}</span>
                <span style={{ ...s.statusPill, color: status.color, background: status.bg }}>
                  {status.icon} {status.label}
                </span>
                {confDelta !== 0 && (
                  <span style={{
                    fontSize: '10px',
                    fontFamily: 'var(--font-mono)',
                    color: confDelta > 0 ? 'var(--success)' : 'var(--danger)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '2px',
                    flexShrink: 0,
                  }}>
                    {confDelta > 0 ? <TrendingUp size={10} /> : <TrendingDown size={10} />}
                    {confDelta > 0 ? '+' : ''}{Math.round(confDelta * 100)}%
                  </span>
                )}
              </div>

              {/* Natural language description (always visible) */}
              <div style={{
                padding: '6px 14px 8px 38px',
                fontSize: '12px',
                lineHeight: '1.6',
                color: 'var(--text-secondary)',
              }}>
                {describeTransform(t)}
              </div>

              {expanded && (
                <>
                  {/* Metrics */}
                  <div style={s.metricRow}>
                    <div style={s.metricItem}>
                      <span style={{ color: 'var(--text-muted)' }}>Confidence</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {Math.round(t.confidence_before * 100)}% → {Math.round(t.confidence_after * 100)}%
                      </span>
                    </div>
                    <div style={s.metricItem}>
                      <span style={{ color: 'var(--text-muted)' }}>Readability</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {Math.round(t.readability_before * 100)}% → {Math.round(t.readability_after * 100)}%
                      </span>
                    </div>
                  </div>

                  {/* Planner reasoning */}
                  {t.reason && (
                    <div style={s.reasonBlock}>
                      <div style={{ fontSize: '10px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '4px' }}>
                        Why this was chosen
                      </div>
                      {t.reason}
                    </div>
                  )}

                  {/* Outputs detail */}
                  {t.outputs && Object.keys(t.outputs).length > 0 && (
                    <div style={s.detailBlock}>
                      {Object.entries(t.outputs).map(([k, v]) => (
                        <div key={k}>
                          <span style={{ color: 'var(--accent)' }}>{k}</span>: {typeof v === 'string' ? v : JSON.stringify(v)}
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          );
        })
      )}
    </div>
  );
}
