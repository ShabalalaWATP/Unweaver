import { useState, useCallback, useEffect } from 'react';
import { RotateCcw, Download, Trash2, Save, Cpu, Eye, Zap } from 'lucide-react';
import type { SampleDetail, AnalysisState } from '@/types';
import ConfidenceGauge from '@/components/common/ConfidenceGauge';
import { useToast } from '@/components/common/Toast';
import * as api from '@/services/api';
import signalChamberGraphic from '@/assets/graphics/signal-chamber.svg';
import { parseWorkspaceBundle } from '@/utils/workspaceBundle';

interface RightPanelProps {
  sample: SampleDetail;
  analysisState: AnalysisState | null;
  onRefresh: () => void;
}

const s = {
  root: {
    width: 272,
    minWidth: 272,
    background: 'var(--bg-secondary)',
    borderLeft: '1px solid var(--border)',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  } as React.CSSProperties,
  scrollArea: {
    flex: 1,
    overflowY: 'auto',
    padding: '14px',
    display: 'flex',
    flexDirection: 'column',
    gap: '14px',
  } as React.CSSProperties,
  card: {
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: '12px',
  } as React.CSSProperties,
  signalCard: {
    position: 'relative',
    overflow: 'hidden',
    padding: '14px',
    background: 'linear-gradient(165deg, rgba(88,166,255,0.12) 0%, rgba(17,21,28,0.88) 65%)',
    border: '1px solid rgba(88,166,255,0.14)',
    borderRadius: 'var(--radius-lg)',
  } as React.CSSProperties,
  signalLabel: {
    fontSize: '10px',
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.14em',
    color: 'var(--accent-bright)',
    marginBottom: '8px',
  } as React.CSSProperties,
  signalTitle: {
    fontSize: '16px',
    fontWeight: 700,
    color: 'var(--text-primary)',
    lineHeight: 1.2,
    marginBottom: '8px',
    maxWidth: '14ch',
  } as React.CSSProperties,
  signalBody: {
    fontSize: '12px',
    lineHeight: 1.5,
    color: 'var(--text-secondary)',
    maxWidth: '20ch',
  } as React.CSSProperties,
  signalGraphicWrap: {
    marginTop: '14px',
    borderRadius: '16px',
    overflow: 'hidden',
    border: '1px solid rgba(255,255,255,0.08)',
    background: 'rgba(4, 9, 14, 0.4)',
  } as React.CSSProperties,
  signalGraphic: {
    width: '100%',
    display: 'block',
  } as React.CSSProperties,
  signalStats: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
    marginTop: '12px',
  } as React.CSSProperties,
  signalStatChip: {
    padding: '4px 8px',
    borderRadius: '999px',
    background: 'rgba(255,255,255,0.05)',
    border: '1px solid rgba(255,255,255,0.08)',
    fontSize: '10px',
    color: 'var(--text-secondary)',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  sectionTitle: {
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.1em',
    color: 'var(--text-muted)',
    marginBottom: '10px',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  } as React.CSSProperties,
  sectionIcon: {
    opacity: 0.5,
  } as React.CSSProperties,
  badge: {
    display: 'inline-block',
    padding: '3px 10px',
    borderRadius: '10px',
    fontSize: '11px',
    fontWeight: 600,
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  langBadge: {
    background: 'var(--accent-muted)',
    color: 'var(--accent)',
    border: '1px solid rgba(88,166,255,0.2)',
  } as React.CSSProperties,
  techTag: {
    display: 'inline-block',
    padding: '3px 8px',
    margin: '2px 4px 2px 0',
    borderRadius: '10px',
    fontSize: '10px',
    fontWeight: 500,
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    border: '1px solid var(--border)',
    transition: 'all var(--transition-fast)',
  } as React.CSSProperties,
  apiItem: {
    fontFamily: 'var(--font-mono)',
    fontSize: '11px',
    color: 'var(--danger)',
    padding: '3px 0',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  } as React.CSSProperties,
  apiDot: {
    width: 4,
    height: 4,
    borderRadius: '50%',
    background: 'var(--danger)',
    flexShrink: 0,
    boxShadow: '0 0 4px var(--danger)',
  } as React.CSSProperties,
  actions: {
    display: 'flex',
    gap: '6px',
    flexWrap: 'wrap',
  } as React.CSSProperties,
  actionBtn: {
    padding: '5px 10px',
    fontSize: '10px',
    fontWeight: 500,
    borderRadius: 'var(--radius-md)',
    border: '1px solid var(--border)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    cursor: 'pointer',
    transition: 'all var(--transition-fast)',
  } as React.CSSProperties,
  textarea: {
    width: '100%',
    minHeight: 90,
    padding: '8px 10px',
    fontSize: '12px',
    fontFamily: 'var(--font-mono)',
    background: 'var(--bg-tertiary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    color: 'var(--text-primary)',
    outline: 'none',
    resize: 'vertical',
    transition: 'border-color var(--transition-med)',
  } as React.CSSProperties,
  saveBtn: {
    marginTop: '8px',
    padding: '6px 12px',
    fontSize: '11px',
    fontWeight: 600,
    borderRadius: 'var(--radius-md)',
    background: 'var(--accent-muted)',
    color: 'var(--accent)',
    border: '1px solid rgba(88,166,255,0.3)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
    transition: 'all var(--transition-fast)',
  } as React.CSSProperties,
  savedMsg: {
    fontSize: '10px',
    color: 'var(--success)',
    marginLeft: 'auto',
    fontWeight: 500,
  } as React.CSSProperties,
  readabilityBar: {
    height: 6,
    borderRadius: 3,
    background: 'var(--bg-tertiary)',
    overflow: 'hidden',
    marginTop: '6px',
    border: '1px solid var(--border)',
  } as React.CSSProperties,
  readabilityFill: {
    height: '100%',
    borderRadius: 3,
    transition: 'width 0.5s ease',
  } as React.CSSProperties,
  statRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: '11px',
    padding: '3px 0',
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
  statValue: {
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)',
    fontWeight: 600,
  } as React.CSSProperties,
  helperText: {
    marginTop: '8px',
    fontSize: '11px',
    color: 'var(--text-muted)',
    lineHeight: '1.55',
  } as React.CSSProperties,
};

function getReadabilityColor(val: number): string {
  if (val >= 0.7) return 'var(--success)';
  if (val >= 0.4) return 'var(--warning)';
  return 'var(--danger)';
}

function countOrNull(value: number | undefined, fallback: number | undefined): number | null {
  if (typeof value === 'number') return value;
  if (typeof fallback === 'number') return fallback;
  return null;
}

export default function RightPanel({ sample, analysisState, onRefresh }: RightPanelProps) {
  const [notes, setNotes] = useState(sample.analyst_notes ?? '');
  const [saved, setSaved] = useState(false);
  const [savingAnalysis, setSavingAnalysis] = useState(false);
  const toast = useToast();

  useEffect(() => {
    setNotes(sample.analyst_notes ?? '');
    setSaved(false);
  }, [sample.id, sample.analyst_notes]);

  const handleSaveNotes = useCallback(async () => {
    try {
      await api.saveNotes(sample.id, notes);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      toast.success('Notes saved');
    } catch {
      toast.error('Failed to save notes');
    }
  }, [sample.id, notes, toast]);

  const savedAnalysis = sample.saved_analysis;
  const confidence = analysisState?.confidence ?? null;
  const overallConfidence = confidence
    ? Math.round(confidence.overall * 100)
    : typeof savedAnalysis?.confidence_score === 'number'
      ? Math.round(savedAnalysis.confidence_score * 100)
      : null;
  const readability = analysisState?.transform_history?.length
    ? analysisState.transform_history[analysisState.transform_history.length - 1].readability_after
    : 0;
  const techniques = analysisState?.detected_techniques ?? [];
  const suspiciousApis = analysisState?.suspicious_apis ?? [];
  const parsedWorkspace = sample.language === 'workspace'
    ? parseWorkspaceBundle(sample.recovered_text ?? '') ?? parseWorkspaceBundle(sample.original_text)
    : null;
  const workspaceContext = analysisState?.workspace_context
    ?? savedAnalysis?.workspace_context
    ?? (parsedWorkspace
      ? {
        ...parsedWorkspace,
        files_preview: parsedWorkspace.files.slice(0, 12).map((file) => ({
          path: file.path,
          language: file.language,
          priority: file.priority,
          size_bytes: file.size_bytes,
        })),
      }
      : null);
  const workspaceGraphSummary = workspaceContext?.graph_summary;
  const workspaceHotspots = workspaceContext
    ? Array.from(
      new Set([
        ...(workspaceContext.symbol_hotspots ?? []),
        ...(workspaceContext.dependency_hotspots ?? []),
      ]),
    )
    : [];
  const workspaceExecutionPaths = workspaceContext?.execution_paths ?? [];
  const indexedFileCount = countOrNull(
    workspaceContext?.indexed_file_count,
    workspaceContext?.included_files,
  );
  const bundledFileCount = countOrNull(
    workspaceContext?.bundle_file_count ?? workspaceContext?.bundled_file_count,
    workspaceContext?.included_files,
  );
  const targetedFileCount = countOrNull(
    workspaceContext?.targeted_file_count,
    workspaceContext?.targeted_files?.length,
  );
  const recoveredFileCount = countOrNull(
    workspaceContext?.deobfuscated_file_count,
    workspaceContext?.deobfuscated_files?.length,
  );
  const deferredHotspotCount = countOrNull(
    workspaceContext?.remaining_frontier_paths?.length,
    undefined,
  );
  const languageLabel = sample.language === 'workspace' ? 'Workspace Bundle' : (sample.language ?? 'Unknown');

  const handleReanalyse = useCallback(async () => {
    try {
      await api.startAnalysis(sample.id);
      onRefresh();
      toast.info('Re-analysis started');
    } catch {
      toast.error('Failed to start re-analysis');
    }
  }, [sample.id, onRefresh, toast]);

  const handleExport = useCallback(async () => {
    try {
      const data = await api.exportJSON(sample.id);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${sample.filename}-report.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('Report exported');
    } catch {
      toast.error('Failed to export report');
    }
  }, [sample, toast]);

  const handleSaveAnalysis = useCallback(async () => {
    setSavingAnalysis(true);
    try {
      await api.saveAnalysisSnapshot(sample.id);
      onRefresh();
      toast.success('Analysis snapshot saved');
    } catch {
      toast.error('Failed to save analysis snapshot');
    } finally {
      setSavingAnalysis(false);
    }
  }, [sample.id, onRefresh, toast]);

  return (
    <div style={s.root}>
      <div style={s.scrollArea}>
        <div className="unweaver-card unweaver-signal-panel" style={s.signalCard}>
          <div style={s.signalLabel}>Live Surface</div>
          <div style={s.signalTitle}>Deobfuscation field for the current sample.</div>
          <div style={s.signalBody}>
            Read deobfuscation confidence, risky APIs, and workspace scope at a glance before you drill into the tabs.
          </div>
          <div style={s.signalGraphicWrap}>
            <img
              src={signalChamberGraphic}
              alt="Abstract signal chamber"
              style={s.signalGraphic}
            />
          </div>
          <div style={s.signalStats}>
            <span style={s.signalStatChip}>
              conf {overallConfidence !== null ? `${overallConfidence}%` : 'n/a'}
            </span>
            <span style={s.signalStatChip}>
              tech {techniques.length}
            </span>
            <span style={s.signalStatChip}>
              apis {suspiciousApis.length}
            </span>
          </div>
        </div>

        {/* Language */}
        <div className="unweaver-card" style={s.card}>
          <div style={s.sectionTitle}>
            <Cpu size={11} style={s.sectionIcon} />
            Language
          </div>
          <span style={{ ...s.badge, ...s.langBadge }}>
            {languageLabel}
          </span>
        </div>

        {/* Confidence */}
        {overallConfidence !== null && (
          <div className="unweaver-card" style={s.card}>
            <div style={s.sectionTitle}>
              <Eye size={11} style={s.sectionIcon} />
              Confidence
            </div>
            <ConfidenceGauge value={overallConfidence} />
            {confidence && (
              <div style={{ marginTop: '10px' }}>
                <div style={s.statRow}>
                  <span>Naming</span>
                  <span style={s.statValue}>{Math.round(confidence.naming * 100)}%</span>
                </div>
                <div style={s.statRow}>
                  <span>Structure</span>
                  <span style={s.statValue}>{Math.round(confidence.structure * 100)}%</span>
                </div>
                <div style={s.statRow}>
                  <span>Strings</span>
                  <span style={s.statValue}>{Math.round(confidence.strings * 100)}%</span>
                </div>
              </div>
            )}
            {sample.language === 'workspace' && workspaceContext && (
              <div style={s.helperText}>
                Confidence reflects the bundled files and targeted hotspots that were analyzed, not every archived file.
              </div>
            )}
          </div>
        )}

        {/* Readability */}
        {readability > 0 && (
          <div className="unweaver-card" style={s.card}>
            <div style={s.sectionTitle}>
              <Zap size={11} style={s.sectionIcon} />
              Readability
            </div>
            <div style={s.statRow}>
              <span>Score</span>
              <span style={{ ...s.statValue, color: getReadabilityColor(readability) }}>
                {Math.round(readability * 100)}%
              </span>
            </div>
            <div style={s.readabilityBar}>
              <div
                style={{
                  ...s.readabilityFill,
                  width: `${readability * 100}%`,
                  background: `linear-gradient(90deg, ${getReadabilityColor(readability)}, ${getReadabilityColor(readability)}cc)`,
                }}
              />
            </div>
          </div>
        )}

        {/* Detected techniques */}
        {techniques.length > 0 && (
          <div className="unweaver-card" style={s.card}>
            <div style={s.sectionTitle}>Detected Techniques</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
              {techniques.map((t, i) => (
                <span key={i} style={s.techTag}>
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {sample.language === 'workspace' && workspaceContext && (
          <div className="unweaver-card" style={s.card}>
            <div style={s.sectionTitle}>Workspace</div>
            {indexedFileCount !== null && (
              <div style={s.statRow}>
                <span>Indexed files</span>
                <span style={s.statValue}>{indexedFileCount}</span>
              </div>
            )}
            {bundledFileCount !== null && (
              <div style={s.statRow}>
                <span>Bundled files</span>
                <span style={s.statValue}>{bundledFileCount}</span>
              </div>
            )}
            {targetedFileCount !== null && (
              <div style={s.statRow}>
                <span>Targeted files</span>
                <span style={s.statValue}>{targetedFileCount}</span>
              </div>
            )}
            {recoveredFileCount !== null && (
              <div style={s.statRow}>
                <span>Recovered files</span>
                <span style={s.statValue}>{recoveredFileCount}</span>
              </div>
            )}
            {deferredHotspotCount !== null && (
              <div style={s.statRow}>
                <span>Deferred hotspots</span>
                <span style={s.statValue}>{deferredHotspotCount}</span>
              </div>
            )}
            {'omitted_files' in workspaceContext && (
              <div style={s.statRow}>
                <span>Omitted files</span>
                <span style={s.statValue}>{workspaceContext.omitted_files ?? 0}</span>
              </div>
            )}
            {typeof workspaceContext.local_dependency_count === 'number' && (
              <div style={s.statRow}>
                <span>Local imports</span>
                <span style={s.statValue}>{workspaceContext.local_dependency_count}</span>
              </div>
            )}
            {typeof workspaceContext.cross_file_call_count === 'number' && (
              <div style={s.statRow}>
                <span>Cross-file calls</span>
                <span style={s.statValue}>{workspaceContext.cross_file_call_count}</span>
              </div>
            )}
            {typeof workspaceGraphSummary?.execution_paths === 'number' && (
              <div style={s.statRow}>
                <span>Execution paths</span>
                <span style={s.statValue}>{workspaceGraphSummary.execution_paths}</span>
              </div>
            )}
            {!!workspaceContext.entry_points?.length && (
              <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                Entrypoints: {workspaceContext.entry_points.slice(0, 4).join(', ')}
              </div>
            )}
            {!!workspaceContext.suspicious_files?.length && (
              <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--danger)' }}>
                Suspicious: {workspaceContext.suspicious_files.slice(0, 3).join(', ')}
              </div>
            )}
            {!!workspaceHotspots.length && (
              <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--accent)', lineHeight: '1.55' }}>
                Hotspots: {workspaceHotspots.slice(0, 4).join(', ')}
              </div>
            )}
            {!!workspaceExecutionPaths.length && (
              <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-secondary)', lineHeight: '1.55' }}>
                Execution path: {workspaceExecutionPaths[0]}
              </div>
            )}
            {!!workspaceContext.files_preview?.length && (
              <div style={{ marginTop: '10px', fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.55' }}>
                Visible bundle files: {workspaceContext.files_preview.slice(0, 4).map((file) => file.path).join(', ')}
              </div>
            )}
          </div>
        )}

        {/* Suspicious APIs */}
        {suspiciousApis.length > 0 && (
          <div style={s.card}>
            <div style={s.sectionTitle}>Suspicious APIs</div>
            {suspiciousApis.map((a, i) => (
              <div key={i} style={s.apiItem}>
                <div style={s.apiDot} />
                {a}
              </div>
            ))}
          </div>
        )}

        {/* Quick actions */}
        <div style={s.card}>
          <div style={s.sectionTitle}>Quick Actions</div>
          <div style={s.actions}>
            <button
              style={{
                ...s.actionBtn,
                opacity: savingAnalysis ? 0.5 : 1,
              }}
              onClick={handleSaveAnalysis}
              title="Save analysis snapshot"
              disabled={savingAnalysis}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--accent)';
                e.currentTarget.style.color = 'var(--accent)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border)';
                e.currentTarget.style.color = 'var(--text-secondary)';
              }}
            >
              <Save size={10} />
              {savingAnalysis ? 'Saving...' : 'Save Analysis'}
            </button>
            <button
              style={s.actionBtn}
              onClick={handleReanalyse}
              title="Re-analyse"
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--accent)';
                e.currentTarget.style.color = 'var(--accent)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border)';
                e.currentTarget.style.color = 'var(--text-secondary)';
              }}
            >
              <RotateCcw size={10} />
              Re-analyse
            </button>
            <button
              style={s.actionBtn}
              onClick={handleExport}
              title="Export"
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--accent)';
                e.currentTarget.style.color = 'var(--accent)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border)';
                e.currentTarget.style.color = 'var(--text-secondary)';
              }}
            >
              <Download size={10} />
              Export
            </button>
            <button
              style={{ ...s.actionBtn, borderColor: 'rgba(248,81,73,0.2)', color: 'var(--danger)' }}
              onClick={onRefresh}
              title="Refresh"
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--danger)';
                e.currentTarget.style.background = 'var(--danger-muted)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'rgba(248,81,73,0.2)';
                e.currentTarget.style.background = 'var(--bg-tertiary)';
              }}
            >
              <Trash2 size={10} />
              Refresh
            </button>
          </div>
          {sample.saved_analysis_at && (
            <div style={{ marginTop: '10px', fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.5' }}>
              Saved analysis available from {new Date(sample.saved_analysis_at).toLocaleString('en-GB')}.
            </div>
          )}
        </div>

        {/* Analyst notes */}
        <div style={s.card}>
          <div style={s.sectionTitle}>
            Analyst Notes
            {saved && <span style={s.savedMsg}>Saved</span>}
          </div>
          <textarea
            style={s.textarea}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Enter notes..."
          />
          <button
            style={s.saveBtn}
            onClick={handleSaveNotes}
            onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(88,166,255,0.15)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = 'var(--accent-muted)'; }}
          >
            <Save size={10} />
            Save Notes
          </button>
        </div>
      </div>
    </div>
  );
}
