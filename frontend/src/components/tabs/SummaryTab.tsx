import { useState, useCallback, useEffect } from 'react';
import type { AISummaryReport, AnalysisState, SampleDetail } from '@/types';
import * as api from '@/services/api';
import reportCascadeGraphic from '@/assets/graphics/report-cascade.svg';

interface SummaryTabProps {
  sample: SampleDetail;
  analysisState: AnalysisState | null;
}

const s = {
  root: {
    height: '100%',
    overflow: 'auto',
    padding: '24px',
    fontFamily: 'var(--font-ui)',
  } as React.CSSProperties,
  hero: {
    position: 'relative',
    overflow: 'hidden',
    borderRadius: '28px',
    marginBottom: '18px',
    background: 'linear-gradient(160deg, rgba(88,166,255,0.12) 0%, rgba(8,14,20,0.92) 72%)',
    border: '1px solid rgba(88,166,255,0.12)',
    padding: '22px',
    minHeight: 220,
  } as React.CSSProperties,
  heroGraphic: {
    position: 'absolute',
    inset: 0,
    width: '100%',
    height: '100%',
    objectFit: 'cover',
    opacity: 0.52,
    pointerEvents: 'none',
  } as React.CSSProperties,
  heroOverlay: {
    position: 'absolute',
    inset: 0,
    background: 'linear-gradient(90deg, rgba(9,17,26,0.88) 0%, rgba(9,17,26,0.54) 48%, rgba(9,17,26,0.2) 100%)',
  } as React.CSSProperties,
  heroContent: {
    position: 'relative',
    zIndex: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: '14px',
    maxWidth: '520px',
  } as React.CSSProperties,
  heroEyebrow: {
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.16em',
    color: 'var(--accent-bright)',
    fontWeight: 700,
  } as React.CSSProperties,
  header: {
    fontSize: '28px',
    fontWeight: 700,
    color: 'var(--text-primary)',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    lineHeight: 1,
  } as React.CSSProperties,
  badge: {
    fontSize: '10px',
    fontWeight: 600,
    padding: '2px 8px',
    borderRadius: 'var(--radius-sm)',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
  } as React.CSSProperties,
  heroSubtext: {
    fontSize: '13px',
    lineHeight: '1.6',
    color: 'var(--text-secondary)',
    maxWidth: '38ch',
  } as React.CSSProperties,
  heroStrip: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
  } as React.CSSProperties,
  heroChip: {
    padding: '4px 9px',
    borderRadius: '999px',
    background: 'rgba(255,255,255,0.05)',
    border: '1px solid rgba(255,255,255,0.08)',
    color: 'var(--text-secondary)',
    fontSize: '10px',
    fontFamily: 'var(--font-mono)',
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
  sectionGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
    gap: '10px',
    marginTop: '14px',
  } as React.CSSProperties,
  sectionCard: {
    padding: '14px',
    borderRadius: '18px',
    background: 'var(--bg-surface)',
    border: '1px solid var(--border-subtle)',
  } as React.CSSProperties,
  sectionTitle: {
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.12em',
    color: 'var(--accent-bright)',
    fontWeight: 700,
    marginBottom: '8px',
  } as React.CSSProperties,
  sectionBody: {
    fontSize: '12px',
    lineHeight: '1.65',
    color: 'var(--text-primary)',
    whiteSpace: 'pre-wrap',
  } as React.CSSProperties,
  confidencePill: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '8px',
    padding: '5px 10px',
    borderRadius: '999px',
    background: 'rgba(255,255,255,0.05)',
    border: '1px solid rgba(255,255,255,0.08)',
    fontSize: '11px',
    color: 'var(--text-secondary)',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  savedNote: {
    fontSize: '11px',
    color: 'var(--text-muted)',
    lineHeight: '1.5',
    marginTop: '8px',
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
    case 'ready':
      return { color: 'var(--warning)', bg: 'var(--warning-muted)' };
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
  const [aiSummary, setAiSummary] = useState<AISummaryReport | null>(sample.saved_analysis?.ai_summary ?? null);
  const [generating, setGenerating] = useState(false);
  const savedAnalysis = sample.saved_analysis;

  useEffect(() => {
    setAiSummary(sample.saved_analysis?.ai_summary ?? null);
  }, [sample.id, sample.saved_analysis]);

  const fallbackNarrative = analysisState?.analysis_summary ?? savedAnalysis?.analysis_summary ?? null;

  const generateSummary = useCallback(async () => {
    setGenerating(true);
    try {
      const result = await api.generateSummary(sample.id);
      setAiSummary(result);
    } catch {
      setAiSummary(null);
    } finally {
      setGenerating(false);
    }
  }, [sample.id, analysisState]);

  if (!analysisState && !savedAnalysis) {
    return (
      <div style={s.emptyState}>
        <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-secondary)' }}>
          No analysis results yet
        </div>
        <div>Run analysis to generate a summary</div>
      </div>
    );
  }

  const confidence = analysisState?.confidence ?? {
    overall: savedAnalysis?.confidence_score ?? 0,
    naming: 0,
    structure: 0,
    strings: 0,
  };
  const transforms = analysisState?.transform_history ?? [];
  const techniques = analysisState?.detected_techniques ?? [];
  const suggestions = analysisState?.llm_suggestions ?? [];
  const iterState = analysisState?.iteration_state;
  const statusBadge = getStatusBadge(sample.status);

  const successCount = transforms.filter((t) => t.success && !t.retry_revert).length;
  const revertCount = transforms.filter((t) => t.retry_revert).length;
  const failCount = transforms.filter((t) => !t.success && !t.retry_revert).length;

  return (
    <div style={s.root}>
      <div style={s.hero}>
        <img
          className="unweaver-summary-atlas"
          src={reportCascadeGraphic}
          alt="Summary report backdrop"
          style={s.heroGraphic}
        />
        <div style={s.heroOverlay} />
        <div style={s.heroContent}>
          <div style={s.heroEyebrow}>Deobfuscation Report</div>
          <div style={s.header}>
            Analysis Report
            <span style={{ ...s.badge, color: statusBadge.color, background: statusBadge.bg }}>
              {sample.status}
            </span>
          </div>
          <div style={s.heroSubtext}>
            Review the current deobfuscation pass, transform quality, confidence profile, and model guidance before exporting recovered output.
          </div>
          <div style={s.heroStrip}>
            <span style={s.heroChip}>{sample.language ?? 'unknown'}</span>
            <span style={s.heroChip}>iter {iterState?.current_iteration ?? 0}</span>
            <span style={s.heroChip}>tech {techniques.length}</span>
            <span style={s.heroChip}>transforms {transforms.length}</span>
          </div>
        </div>
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
              {aiSummary ? 'Regenerate AI Analysis' : 'Generate AI Analysis'}
            </button>
          )}
        </div>
        {generating ? (
          <div style={s.generatingText}>Generating AI deobfuscation analysis...</div>
        ) : aiSummary ? (
          <>
            <div style={s.aiSummary}>{aiSummary.summary}</div>
            {sample.saved_analysis_at && (
              <div style={s.savedNote}>
                Saved analysis available from {new Date(sample.saved_analysis_at).toLocaleString('en-GB')}.
              </div>
            )}
            <div style={s.sectionGrid}>
              <div style={s.sectionCard}>
                <div style={s.sectionTitle}>Deobfuscation</div>
                <div style={s.sectionBody}>{aiSummary.sections.deobfuscation_analysis}</div>
              </div>
              <div style={s.sectionCard}>
                <div style={s.sectionTitle}>Original Intent</div>
                <div style={s.sectionBody}>{aiSummary.sections.inferred_original_intent}</div>
              </div>
              <div style={s.sectionCard}>
                <div style={s.sectionTitle}>Actual Behavior</div>
                <div style={s.sectionBody}>{aiSummary.sections.actual_behavior}</div>
              </div>
              <div style={s.sectionCard}>
                <div style={s.sectionTitle}>Recovered Output Confidence</div>
                <div style={s.sectionBody}>{aiSummary.sections.confidence_assessment}</div>
                {typeof aiSummary.confidence_score === 'number' && (
                  <div style={{ ...s.confidencePill, marginTop: '10px' }}>
                    AI confidence {Math.round(aiSummary.confidence_score * 100)}%
                  </div>
                )}
              </div>
            </div>
          </>
        ) : fallbackNarrative ? (
          <>
            <div style={s.aiSummary}>{fallbackNarrative}</div>
            {sample.saved_analysis_at && (
              <div style={s.savedNote}>
                Restored from the saved analysis snapshot captured on {new Date(sample.saved_analysis_at).toLocaleString('en-GB')}.
              </div>
            )}
          </>
        ) : (
          <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
            Generate an AI analysis to explain the obfuscation, inferred original intent, actual recovered behavior, and confidence in the recovered output.
          </div>
        )}
      </div>

      {/* LLM Obfuscation Classification */}
      {analysisState?.iteration_state?.llm_classification && (() => {
        const cls = analysisState.iteration_state.llm_classification as Record<string, unknown>;
        const obfType = cls.obfuscation_type as string | undefined;
        const tools = (cls.tools_identified as string[]) ?? [];
        const layers = (cls.layers as string[]) ?? [];
        const strategy = cls.recommended_strategy as string | undefined;
        const clsConf = typeof cls.confidence === 'number' ? cls.confidence : null;
        return (
          <div className="unweaver-card" style={{ ...s.card, borderLeft: '3px solid var(--accent)' }}>
            <div style={s.cardTitle}>LLM Obfuscation Classification</div>
            {obfType && (
              <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '8px' }}>
                {obfType}
              </div>
            )}
            {strategy && (
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.6', marginBottom: '10px' }}>
                {strategy}
              </div>
            )}
            {tools.length > 0 && (
              <div style={{ marginBottom: '8px' }}>
                <span style={{ fontSize: '10px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Identified Tools
                </span>
                <div style={{ ...s.techniqueList, marginTop: '4px' }}>
                  {tools.map((t, i) => (
                    <span key={i} style={{ ...s.techniqueTag, background: 'var(--danger-muted)', color: 'var(--danger)', border: '1px solid rgba(248,81,73,0.2)' }}>
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {layers.length > 0 && (
              <div style={{ marginBottom: '8px' }}>
                <span style={{ fontSize: '10px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Obfuscation Layers
                </span>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px', alignItems: 'center' }}>
                  {layers.map((layer, i) => (
                    <span key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ fontSize: '11px', fontWeight: 500, padding: '2px 8px', borderRadius: 'var(--radius-sm)', background: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                        {layer}
                      </span>
                      {i < layers.length - 1 && <span style={{ color: 'var(--text-muted)', fontSize: '10px' }}>→</span>}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {clsConf !== null && (
              <div style={s.confidencePill}>
                Classification confidence {Math.round(clsConf * 100)}%
              </div>
            )}
          </div>
        );
      })()}

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
