import { useState, useEffect, useCallback } from 'react';
import type { AnalysisState, SampleDetail } from '@/types';
import * as api from '@/services/api';

interface SummaryTabProps {
  sample: SampleDetail;
  analysisState: AnalysisState | null;
}

const s = {
  root: {
    height: '100%',
    overflow: 'auto',
    padding: '20px',
    fontFamily: 'var(--font-ui)',
  } as React.CSSProperties,
  header: {
    fontSize: '16px',
    fontWeight: 700,
    color: 'var(--text-primary)',
    marginBottom: '16px',
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
  } as React.CSSProperties,
  badge: {
    fontSize: '10px',
    fontWeight: 600,
    padding: '2px 8px',
    borderRadius: 'var(--radius-sm)',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
  } as React.CSSProperties,
  card: {
    background: 'var(--bg-card)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: '16px',
    marginBottom: '14px',
    boxShadow: 'var(--shadow-card)',
  } as React.CSSProperties,
  cardTitle: {
    fontSize: '11px',
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: 'var(--text-muted)',
    marginBottom: '10px',
  } as React.CSSProperties,
  summaryText: {
    fontSize: '13px',
    lineHeight: '1.7',
    color: 'var(--text-primary)',
    whiteSpace: 'pre-wrap',
  } as React.CSSProperties,
  metricGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
    gap: '10px',
  } as React.CSSProperties,
  metric: {
    background: 'var(--bg-surface)',
    borderRadius: 'var(--radius-md)',
    padding: '12px',
    textAlign: 'center',
  } as React.CSSProperties,
  metricValue: {
    fontSize: '22px',
    fontWeight: 700,
    fontFamily: 'var(--font-mono)',
    color: 'var(--accent)',
    lineHeight: '1.2',
  } as React.CSSProperties,
  metricLabel: {
    fontSize: '10px',
    fontWeight: 600,
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    marginTop: '4px',
  } as React.CSSProperties,
  techniqueList: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '6px',
    marginTop: '4px',
  } as React.CSSProperties,
  techniqueTag: {
    fontSize: '11px',
    fontWeight: 500,
    padding: '3px 10px',
    borderRadius: 'var(--radius-sm)',
    background: 'var(--accent-muted)',
    color: 'var(--accent)',
    border: '1px solid var(--accent-border)',
  } as React.CSSProperties,
  suggestionItem: {
    fontSize: '12px',
    color: 'var(--text-secondary)',
    padding: '4px 0',
    lineHeight: '1.5',
    borderBottom: '1px solid var(--border-subtle)',
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
  aiSummary: {
    fontSize: '13px',
    lineHeight: '1.8',
    color: 'var(--text-primary)',
    whiteSpace: 'pre-wrap',
  } as React.CSSProperties,
  generateBtn: {
    padding: '8px 16px',
    fontSize: '12px',
    fontWeight: 600,
    borderRadius: 'var(--radius-md)',
    background: 'var(--accent-solid)',
    color: '#fff',
    border: 'none',
    cursor: 'pointer',
    transition: 'all 0.15s ease',
  } as React.CSSProperties,
  generatingText: {
    fontSize: '12px',
    color: 'var(--text-muted)',
    fontStyle: 'italic',
  } as React.CSSProperties,
};

function getConfidenceColor(v: number): string {
  if (v >= 0.7) return 'var(--success)';
  if (v >= 0.4) return 'var(--warning)';
  return 'var(--danger)';
}

function getStatusBadge(status: string): { color: string; bg: string } {
  switch (status) {
    case 'completed':
      return { color: 'var(--success)', bg: 'var(--success-muted)' };
    case 'failed':
      return { color: 'var(--danger)', bg: 'var(--danger-muted)' };
    case 'running':
      return { color: 'var(--accent)', bg: 'var(--accent-muted)' };
    default:
      return { color: 'var(--text-muted)', bg: 'var(--bg-tertiary)' };
  }
}

export default function SummaryTab({ sample, analysisState }: SummaryTabProps) {
  const [aiSummary, setAiSummary] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);

  // Auto-load AI summary if analysis_summary exists in state
  useEffect(() => {
    if (analysisState?.analysis_summary) {
      setAiSummary(analysisState.analysis_summary);
    }
  }, [analysisState?.analysis_summary]);

  const generateSummary = useCallback(async () => {
    if (!analysisState) return;
    setGenerating(true);
    try {
      const result = await api.generateSummary(sample.id);
      setAiSummary(result);
    } catch {
      setAiSummary('Failed to generate summary. Check LLM provider configuration.');
    } finally {
      setGenerating(false);
    }
  }, [sample.id, analysisState]);

  if (!analysisState) {
    return (
      <div style={s.emptyState}>
        <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-secondary)' }}>
          No analysis results yet
        </div>
        <div>Run analysis to generate a summary</div>
      </div>
    );
  }

  const confidence = analysisState.confidence ?? { overall: 0, naming: 0, structure: 0, strings: 0 };
  const transforms = analysisState.transform_history ?? [];
  const techniques = analysisState.detected_techniques ?? [];
  const suggestions = analysisState.llm_suggestions ?? [];
  const iterState = analysisState.iteration_state;
  const statusBadge = getStatusBadge(sample.status);

  const successCount = transforms.filter((t) => t.success && !t.retry_revert).length;
  const revertCount = transforms.filter((t) => t.retry_revert).length;
  const failCount = transforms.filter((t) => !t.success && !t.retry_revert).length;

  return (
    <div style={s.root}>
      {/* Header */}
      <div style={s.header}>
        Analysis Report
        <span style={{ ...s.badge, color: statusBadge.color, background: statusBadge.bg }}>
          {sample.status}
        </span>
      </div>

      {/* AI Summary */}
      <div className="unweaver-card unweaver-glow-border" style={s.card}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={s.cardTitle}>AI Summary</div>
          {!generating && (
            <button
              style={s.generateBtn}
              onClick={generateSummary}
              onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.85'; }}
              onMouseLeave={(e) => { e.currentTarget.style.opacity = '1'; }}
            >
              {aiSummary ? 'Regenerate' : 'Generate Summary'}
            </button>
          )}
        </div>
        {generating ? (
          <div style={s.generatingText}>Generating AI summary...</div>
        ) : aiSummary ? (
          <div style={s.aiSummary}>{aiSummary}</div>
        ) : (
          <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
            Click "Generate Summary" to create an AI-powered analysis report.
          </div>
        )}
      </div>

      {/* Metrics */}
      <div className="unweaver-card" style={s.card}>
        <div style={s.cardTitle}>Metrics</div>
        <div style={s.metricGrid}>
          <div style={s.metric}>
            <div style={{ ...s.metricValue, color: getConfidenceColor(confidence.overall) }}>
              {Math.round(confidence.overall * 100)}%
            </div>
            <div style={s.metricLabel}>Overall Confidence</div>
          </div>
          <div style={s.metric}>
            <div style={s.metricValue}>{iterState?.current_iteration ?? 0}</div>
            <div style={s.metricLabel}>Iterations</div>
          </div>
          <div style={s.metric}>
            <div style={{ ...s.metricValue, color: 'var(--success)' }}>{successCount}</div>
            <div style={s.metricLabel}>Transforms OK</div>
          </div>
          <div style={s.metric}>
            <div style={{ ...s.metricValue, color: 'var(--warning)' }}>{revertCount}</div>
            <div style={s.metricLabel}>Reverted</div>
          </div>
          <div style={s.metric}>
            <div style={{ ...s.metricValue, color: 'var(--danger)' }}>{failCount}</div>
            <div style={s.metricLabel}>Failed</div>
          </div>
          <div style={s.metric}>
            <div style={s.metricValue}>{techniques.length}</div>
            <div style={s.metricLabel}>Techniques</div>
          </div>
        </div>
      </div>

      {/* Confidence Breakdown */}
      <div className="unweaver-card" style={s.card}>
        <div style={s.cardTitle}>Confidence Breakdown</div>
        {(['naming', 'structure', 'strings'] as const).map((key) => {
          const val = confidence[key] ?? 0;
          return (
            <div key={key} style={{ marginBottom: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '3px' }}>
                <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                  {key}
                </span>
                <span style={{ fontSize: '11px', fontWeight: 600, fontFamily: 'var(--font-mono)', color: getConfidenceColor(val) }}>
                  {Math.round(val * 100)}%
                </span>
              </div>
              <div style={{ height: '4px', borderRadius: '2px', background: 'var(--bg-inset)' }}>
                <div style={{
                  height: '100%',
                  width: `${Math.round(val * 100)}%`,
                  borderRadius: '2px',
                  background: getConfidenceColor(val),
                  transition: 'width 0.3s ease',
                }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Detected Techniques */}
      {techniques.length > 0 && (
        <div className="unweaver-card" style={s.card}>
          <div style={s.cardTitle}>Detected Obfuscation Techniques</div>
          <div style={s.techniqueList}>
            {techniques.map((t, i) => (
              <span key={i} style={s.techniqueTag}>{t}</span>
            ))}
          </div>
        </div>
      )}

      {/* LLM Suggestions */}
      {suggestions.length > 0 && (
        <div className="unweaver-card" style={s.card}>
          <div style={s.cardTitle}>AI Insights ({suggestions.length})</div>
          {suggestions.slice(0, 15).map((sug, i) => (
            <div key={i} style={s.suggestionItem}>{sug}</div>
          ))}
          {suggestions.length > 15 && (
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '6px' }}>
              ... and {suggestions.length - 15} more
            </div>
          )}
        </div>
      )}
    </div>
  );
}
