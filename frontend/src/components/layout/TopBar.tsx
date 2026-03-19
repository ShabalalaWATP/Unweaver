import { useState, useCallback } from 'react';
import { Play, Square, RefreshCw, Download, FileText } from 'lucide-react';
import type { SampleDetail, AnalysisStatus } from '@/types';
import StatusBadge from '@/components/common/StatusBadge';
import * as api from '@/services/api';

interface TopBarProps {
  sample: SampleDetail | null;
  analysisStatus: AnalysisStatus | null;
  onStartAnalysis: () => void;
  onStopAnalysis: () => void;
  onRefresh: () => void;
}

const s = {
  root: {
    height: 48,
    minHeight: 48,
    background: 'var(--bg-secondary)',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    alignItems: 'center',
    padding: '0 16px',
    gap: '12px',
  } as React.CSSProperties,
  title: {
    fontSize: '13px',
    fontWeight: 600,
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-mono)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  } as React.CSSProperties,
  lang: {
    fontSize: '10px',
    padding: '2px 6px',
    borderRadius: 'var(--radius-sm)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    fontWeight: 500,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
  } as React.CSSProperties,
  separator: {
    width: 1,
    height: 20,
    background: 'var(--border)',
    flexShrink: 0,
  } as React.CSSProperties,
  spacer: {
    flex: 1,
  } as React.CSSProperties,
  progress: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '11px',
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
  progressBar: {
    width: 100,
    height: 4,
    background: 'var(--bg-tertiary)',
    borderRadius: 2,
    overflow: 'hidden',
  } as React.CSSProperties,
  progressFill: {
    height: '100%',
    background: 'var(--accent)',
    borderRadius: 2,
    transition: 'width 0.3s ease',
  } as React.CSSProperties,
  btn: {
    padding: '5px 12px',
    fontSize: '11px',
    fontWeight: 600,
    borderRadius: 'var(--radius-sm)',
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
    cursor: 'pointer',
    transition: 'opacity 0.15s',
    border: 'none',
  } as React.CSSProperties,
  analyseBtn: {
    background: 'var(--accent)',
    color: '#fff',
  } as React.CSSProperties,
  stopBtn: {
    background: 'var(--danger-muted)',
    color: 'var(--danger)',
    border: '1px solid var(--danger)',
  } as React.CSSProperties,
  iconBtn: {
    padding: '6px',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    transition: 'color 0.15s, background 0.15s',
  } as React.CSSProperties,
  actionInfo: {
    fontSize: '11px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
};

export default function TopBar({
  sample,
  analysisStatus,
  onStartAnalysis,
  onStopAnalysis,
  onRefresh,
}: TopBarProps) {
  const [exporting, setExporting] = useState(false);

  const isRunning = sample?.status === 'running';
  const isPending = sample?.status === 'pending';
  const canStart = sample && !isRunning && !isPending;

  const handleExportMd = useCallback(async () => {
    if (!sample) return;
    setExporting(true);
    try {
      const md = await api.exportMarkdown(sample.id);
      const blob = new Blob([md], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${sample.filename}-report.md`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export failed:', err);
    } finally {
      setExporting(false);
    }
  }, [sample]);

  const handleExportJson = useCallback(async () => {
    if (!sample) return;
    setExporting(true);
    try {
      const data = await api.exportJSON(sample.id);
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${sample.filename}-report.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export failed:', err);
    } finally {
      setExporting(false);
    }
  }, [sample]);

  if (!sample) {
    return (
      <div style={s.root}>
        <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
          No sample selected
        </span>
      </div>
    );
  }

  return (
    <div style={s.root}>
      <span style={s.title}>{sample.filename}</span>
      {sample.language && <span style={s.lang}>{sample.language}</span>}
      <StatusBadge status={sample.status} />

      {/* Progress indicator during analysis */}
      {isRunning && analysisStatus && (
        <>
          <div style={s.separator} />
          <div style={s.progress}>
            <div style={s.progressBar}>
              <div
                style={{
                  ...s.progressFill,
                  width: `${analysisStatus.progress_pct}%`,
                }}
              />
            </div>
            <span>
              Iter {analysisStatus.current_iteration}/{analysisStatus.total_iterations || '?'}
            </span>
          </div>
          {analysisStatus.current_action && (
            <span style={s.actionInfo}>{analysisStatus.current_action}</span>
          )}
        </>
      )}

      <div style={s.spacer} />

      {/* Action buttons */}
      {isRunning ? (
        <button
          style={{ ...s.btn, ...s.stopBtn }}
          onClick={onStopAnalysis}
        >
          <Square size={12} />
          Stop
        </button>
      ) : (
        <button
          style={{
            ...s.btn,
            ...s.analyseBtn,
            opacity: canStart ? 1 : 0.4,
            cursor: canStart ? 'pointer' : 'default',
          }}
          onClick={canStart ? onStartAnalysis : undefined}
        >
          <Play size={12} />
          Analyse &amp; Deobfuscate
        </button>
      )}

      <div style={s.separator} />

      <button
        style={s.iconBtn}
        onClick={onRefresh}
        title="Refresh"
        onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--text-primary)'; }}
        onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-secondary)'; }}
      >
        <RefreshCw size={14} />
      </button>

      <button
        style={{ ...s.iconBtn, opacity: exporting ? 0.5 : 1 }}
        onClick={handleExportMd}
        title="Export Markdown"
        disabled={exporting}
        onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--text-primary)'; }}
        onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-secondary)'; }}
      >
        <FileText size={14} />
      </button>
      <button
        style={{ ...s.iconBtn, opacity: exporting ? 0.5 : 1 }}
        onClick={handleExportJson}
        title="Export JSON"
        disabled={exporting}
        onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--text-primary)'; }}
        onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-secondary)'; }}
      >
        <Download size={14} />
      </button>
    </div>
  );
}
