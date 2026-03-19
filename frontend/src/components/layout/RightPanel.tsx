import { useState, useCallback, useEffect } from 'react';
import { RotateCcw, Download, Trash2, Save } from 'lucide-react';
import type { SampleDetail, AnalysisState } from '@/types';
import ConfidenceGauge from '@/components/common/ConfidenceGauge';
import * as api from '@/services/api';

interface RightPanelProps {
  sample: SampleDetail;
  analysisState: AnalysisState | null;
  onRefresh: () => void;
}

const s = {
  root: {
    width: 260,
    minWidth: 260,
    background: 'var(--bg-secondary)',
    borderLeft: '1px solid var(--border)',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  } as React.CSSProperties,
  scrollArea: {
    flex: 1,
    overflowY: 'auto',
    padding: '12px',
  } as React.CSSProperties,
  section: {
    marginBottom: '16px',
  } as React.CSSProperties,
  sectionTitle: {
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    color: 'var(--text-muted)',
    marginBottom: '8px',
  } as React.CSSProperties,
  badge: {
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: 'var(--radius-sm)',
    fontSize: '11px',
    fontWeight: 500,
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  langBadge: {
    background: 'var(--accent-muted)',
    color: 'var(--accent)',
  } as React.CSSProperties,
  techTag: {
    display: 'inline-block',
    padding: '2px 6px',
    margin: '2px 4px 2px 0',
    borderRadius: 'var(--radius-sm)',
    fontSize: '10px',
    fontWeight: 500,
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    border: '1px solid var(--border)',
  } as React.CSSProperties,
  apiItem: {
    fontFamily: 'var(--font-mono)',
    fontSize: '11px',
    color: 'var(--danger)',
    padding: '2px 0',
  } as React.CSSProperties,
  actions: {
    display: 'flex',
    gap: '6px',
    flexWrap: 'wrap',
  } as React.CSSProperties,
  actionBtn: {
    padding: '4px 8px',
    fontSize: '10px',
    fontWeight: 500,
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    cursor: 'pointer',
    transition: 'border-color 0.15s',
  } as React.CSSProperties,
  textarea: {
    width: '100%',
    minHeight: 100,
    padding: '8px',
    fontSize: '12px',
    fontFamily: 'var(--font-mono)',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    outline: 'none',
    resize: 'vertical',
  } as React.CSSProperties,
  saveBtn: {
    marginTop: '6px',
    padding: '5px 10px',
    fontSize: '11px',
    fontWeight: 600,
    borderRadius: 'var(--radius-sm)',
    background: 'var(--accent-muted)',
    color: 'var(--accent)',
    border: '1px solid var(--accent)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  } as React.CSSProperties,
  savedMsg: {
    fontSize: '10px',
    color: 'var(--success)',
    marginLeft: '8px',
  } as React.CSSProperties,
  readabilityBar: {
    height: 4,
    borderRadius: 2,
    background: 'var(--bg-tertiary)',
    overflow: 'hidden',
    marginTop: '4px',
  } as React.CSSProperties,
  readabilityFill: {
    height: '100%',
    borderRadius: 2,
    transition: 'width 0.3s ease',
  } as React.CSSProperties,
  statRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: '11px',
    padding: '2px 0',
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
  statValue: {
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)',
    fontWeight: 500,
  } as React.CSSProperties,
};

function getReadabilityColor(val: number): string {
  if (val >= 0.7) return 'var(--success)';
  if (val >= 0.4) return 'var(--warning)';
  return 'var(--danger)';
}

export default function RightPanel({ sample, analysisState, onRefresh }: RightPanelProps) {
  const [notes, setNotes] = useState(sample.analyst_notes ?? '');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setNotes(sample.analyst_notes ?? '');
    setSaved(false);
  }, [sample.id, sample.analyst_notes]);

  const handleSaveNotes = useCallback(async () => {
    await api.saveNotes(sample.id, notes);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }, [sample.id, notes]);

  const confidence = analysisState?.confidence ?? null;
  const overallConfidence = confidence ? Math.round(confidence.overall * 100) : null;
  const readability = analysisState?.transform_history?.length
    ? analysisState.transform_history[analysisState.transform_history.length - 1].readability_after
    : 0;
  const techniques = analysisState?.detected_techniques ?? [];
  const suspiciousApis = analysisState?.suspicious_apis ?? [];

  const handleReanalyse = useCallback(async () => {
    await api.startAnalysis(sample.id);
    onRefresh();
  }, [sample.id, onRefresh]);

  const handleExport = useCallback(async () => {
    const data = await api.exportJSON(sample.id);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${sample.filename}-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [sample]);

  return (
    <div style={s.root}>
      <div style={s.scrollArea}>
        {/* Language */}
        <div style={s.section}>
          <div style={s.sectionTitle}>Language</div>
          <span style={{ ...s.badge, ...s.langBadge }}>
            {sample.language ?? 'Unknown'}
          </span>
        </div>

        {/* Confidence */}
        {overallConfidence !== null && (
          <div style={s.section}>
            <div style={s.sectionTitle}>Confidence</div>
            <ConfidenceGauge value={overallConfidence} />
            {confidence && (
              <div style={{ marginTop: '8px' }}>
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
          </div>
        )}

        {/* Readability */}
        {readability > 0 && (
          <div style={s.section}>
            <div style={s.sectionTitle}>Readability</div>
            <div style={s.statRow}>
              <span>Score</span>
              <span style={s.statValue}>{Math.round(readability * 100)}%</span>
            </div>
            <div style={s.readabilityBar}>
              <div
                style={{
                  ...s.readabilityFill,
                  width: `${readability * 100}%`,
                  background: getReadabilityColor(readability),
                }}
              />
            </div>
          </div>
        )}

        {/* Detected techniques */}
        {techniques.length > 0 && (
          <div style={s.section}>
            <div style={s.sectionTitle}>Detected Techniques</div>
            <div>
              {techniques.map((t, i) => (
                <span key={i} style={s.techTag}>
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Suspicious APIs */}
        {suspiciousApis.length > 0 && (
          <div style={s.section}>
            <div style={s.sectionTitle}>Suspicious APIs</div>
            {suspiciousApis.map((a, i) => (
              <div key={i} style={s.apiItem}>
                {a}
              </div>
            ))}
          </div>
        )}

        {/* Quick actions */}
        <div style={s.section}>
          <div style={s.sectionTitle}>Quick Actions</div>
          <div style={s.actions}>
            <button style={s.actionBtn} onClick={handleReanalyse} title="Re-analyse">
              <RotateCcw size={10} />
              Re-analyse
            </button>
            <button style={s.actionBtn} onClick={handleExport} title="Export">
              <Download size={10} />
              Export
            </button>
            <button
              style={{ ...s.actionBtn, borderColor: 'var(--danger)', color: 'var(--danger)' }}
              onClick={onRefresh}
              title="Refresh"
            >
              <Trash2 size={10} />
              Clear Cache
            </button>
          </div>
        </div>

        {/* Analyst notes */}
        <div style={s.section}>
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
          <button style={s.saveBtn} onClick={handleSaveNotes}>
            <Save size={10} />
            Save Notes
          </button>
        </div>
      </div>
    </div>
  );
}
