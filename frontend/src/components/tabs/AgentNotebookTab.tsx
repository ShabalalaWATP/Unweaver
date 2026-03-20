import type { AnalysisState, TransformRecord } from '@/types';

interface AgentNotebookTabProps {
  analysisState: AnalysisState | null;
}

const s = {
  root: {
    height: '100%',
    overflow: 'auto',
    padding: '16px',
    fontFamily: 'var(--font-mono)',
    fontSize: '12px',
  } as React.CSSProperties,
  entry: {
    marginBottom: '16px',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    overflow: 'hidden',
  } as React.CSSProperties,
  entryHeader: {
    padding: '8px 12px',
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    borderBottom: '1px solid var(--border)',
    background: 'var(--bg-tertiary)',
  } as React.CSSProperties,
  iterLabel: {
    fontSize: '11px',
    fontWeight: 700,
    color: 'var(--accent)',
  } as React.CSSProperties,
  actionLabel: {
    fontSize: '11px',
    fontWeight: 600,
    color: 'var(--text-primary)',
  } as React.CSSProperties,
  statusTag: {
    marginLeft: 'auto',
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: 'var(--radius-sm)',
  } as React.CSSProperties,
  section: {
    padding: '8px 12px',
    borderBottom: '1px solid var(--border)',
  } as React.CSSProperties,
  sectionLabel: {
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: 'var(--text-muted)',
    marginBottom: '4px',
  } as React.CSSProperties,
  text: {
    fontSize: '11px',
    color: 'var(--text-secondary)',
    lineHeight: '1.6',
    whiteSpace: 'pre-wrap',
  } as React.CSSProperties,
  logLine: {
    padding: '3px 12px',
    fontSize: '11px',
    borderLeft: '3px solid transparent',
    lineHeight: '1.5',
  } as React.CSSProperties,
  summary: {
    padding: '12px',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    marginBottom: '16px',
  } as React.CSSProperties,
  summaryTitle: {
    fontSize: '11px',
    fontWeight: 600,
    color: 'var(--text-primary)',
    marginBottom: '6px',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
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

function getStatusStyle(t: TransformRecord): React.CSSProperties {
  if (t.retry_revert)
    return { color: 'var(--warning)', background: 'var(--warning-muted)' };
  if (t.success)
    return { color: 'var(--success)', background: 'var(--success-muted)' };
  return { color: 'var(--danger)', background: 'var(--danger-muted)' };
}

function getStatusLabel(t: TransformRecord): string {
  if (t.retry_revert) return 'REVERTED';
  if (t.success) return 'SUCCESS';
  return 'FAILED';
}

function getDecisionColor(action: string): string {
  const lower = action.toLowerCase();
  if (lower.includes('rename') || lower.includes('symbol')) return 'var(--accent)';
  if (lower.includes('decode') || lower.includes('base64') || lower.includes('hex'))
    return 'var(--success)';
  if (lower.includes('deobfuscate') || lower.includes('unpack')) return 'var(--warning)';
  if (lower.includes('string') || lower.includes('extract')) return 'var(--purple)';
  return 'var(--text-secondary)';
}

export default function AgentNotebookTab({ analysisState }: AgentNotebookTabProps) {
  if (!analysisState) {
    return (
      <div style={s.emptyState}>
        <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-secondary)' }}>
          No agent log available
        </div>
        <div>Run analysis to populate the agent notebook</div>
      </div>
    );
  }

  const transforms = analysisState.transform_history ?? [];
  const suggestions = analysisState.llm_suggestions ?? [];
  const iterState = analysisState.iteration_state ?? {
    current_iteration: 0,
    stall_counter: 0,
    last_confidence: 0,
    stopped: false,
  };

  return (
    <div style={s.root}>
      {/* Summary block */}
      {analysisState.analysis_summary && (
        <div style={s.summary}>
          <div style={s.summaryTitle}>Analysis Summary</div>
          <div style={s.text}>{analysisState.analysis_summary}</div>
        </div>
      )}

      {/* Iteration state */}
      <div style={s.summary}>
        <div style={s.summaryTitle}>Orchestrator State</div>
        <div style={s.text}>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Iteration: </span>
            <span style={{ color: 'var(--accent)' }}>{iterState.current_iteration}</span>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Stall counter: </span>
            <span style={{ color: iterState.stall_counter > 2 ? 'var(--warning)' : 'var(--text-primary)' }}>
              {iterState.stall_counter}
            </span>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Last confidence: </span>
            <span>{Math.round(iterState.last_confidence * 100)}%</span>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Stopped: </span>
            <span style={{ color: iterState.stopped ? 'var(--danger)' : 'var(--success)' }}>
              {iterState.stopped ? 'Yes' : 'No'}
            </span>
          </div>
        </div>
      </div>

      {/* LLM suggestions */}
      {suggestions.length > 0 && (
        <div style={s.summary}>
          <div style={s.summaryTitle}>LLM Suggestions</div>
          {suggestions.map((sug, i) => (
            <div
              key={i}
              style={{
                ...s.logLine,
                borderLeftColor: 'var(--accent)',
                color: 'var(--text-secondary)',
              }}
            >
              {sug}
            </div>
          ))}
        </div>
      )}

      {/* Transform decision log */}
      {transforms.length === 0 ? (
        <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>
          No iterations recorded yet
        </div>
      ) : (
        transforms.map((t) => (
          <div key={t.iteration} style={s.entry}>
            <div style={s.entryHeader}>
              <span style={s.iterLabel}>ITER #{t.iteration}</span>
              <span style={{ ...s.actionLabel, color: getDecisionColor(t.action) }}>
                {t.action}
              </span>
              <span style={{ ...s.statusTag, ...getStatusStyle(t) }}>
                {getStatusLabel(t)}
              </span>
            </div>

            {/* Planner decision */}
            {t.reason && (
              <div style={s.section}>
                <div style={s.sectionLabel}>Planner Reasoning</div>
                <div style={s.text}>{t.reason}</div>
              </div>
            )}

            {/* Metrics */}
            <div style={s.section}>
              <div style={s.sectionLabel}>Metrics</div>
              <div style={s.text}>
                <span style={{ color: 'var(--text-muted)' }}>Confidence: </span>
                {Math.round(t.confidence_before * 100)}% {'->'} {Math.round(t.confidence_after * 100)}%
                {'  '}
                <span style={{ color: 'var(--text-muted)' }}>Readability: </span>
                {Math.round(t.readability_before * 100)}% {'->'} {Math.round(t.readability_after * 100)}%
              </div>
            </div>

            {/* I/O preview */}
            {(Object.keys(t.inputs).length > 0 || Object.keys(t.outputs).length > 0) && (
              <div style={{ ...s.section, borderBottom: 'none' }}>
                <div style={s.sectionLabel}>Action I/O</div>
                {Object.keys(t.inputs).length > 0 && (
                  <div style={{ ...s.text, marginBottom: '4px' }}>
                    <span style={{ color: 'var(--text-muted)' }}>In: </span>
                    {JSON.stringify(t.inputs)}
                  </div>
                )}
                {Object.keys(t.outputs).length > 0 && (
                  <div style={s.text}>
                    <span style={{ color: 'var(--text-muted)' }}>Out: </span>
                    {JSON.stringify(t.outputs)}
                  </div>
                )}
              </div>
            )}
          </div>
        ))
      )}
    </div>
  );
}
