import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { Play, Square, RefreshCw, Download, FileText, FileCode, Loader2, FolderOpen, Search, ChevronDown } from 'lucide-react';
import type { SampleDetail, AnalysisStatus, Project } from '@/types';
import StatusBadge from '@/components/common/StatusBadge';
import * as api from '@/services/api';
import { parseWorkspaceBundle } from '@/utils/workspaceBundle';

interface TopBarProps {
  projects: Project[];
  selectedProjectId: string | null;
  onSelectProject: (id: string) => void;
  sample: SampleDetail | null;
  analysisStatus: AnalysisStatus | null;
  onStartAnalysis: () => void;
  onStopAnalysis: () => void;
  onRefresh: () => void;
}

const s = {
  root: {
    height: 52,
    minHeight: 52,
    background: 'rgba(17,21,28,0.75)',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    alignItems: 'center',
    padding: '0 16px',
    gap: '12px',
    position: 'relative',
    backdropFilter: 'blur(12px) saturate(1.2)',
    WebkitBackdropFilter: 'blur(12px) saturate(1.2)',
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
  projectButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '6px 10px',
    borderRadius: '14px',
    border: '1px solid var(--border)',
    background: 'rgba(255,255,255,0.04)',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    transition: 'all var(--transition-fast)',
    minWidth: 0,
    maxWidth: 240,
  } as React.CSSProperties,
  projectButtonText: {
    minWidth: 0,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    fontSize: '11px',
    fontWeight: 600,
    color: 'var(--text-primary)',
  } as React.CSSProperties,
  projectSwitcher: {
    position: 'relative',
    flexShrink: 0,
  } as React.CSSProperties,
  projectMenu: {
    position: 'absolute',
    top: 'calc(100% + 10px)',
    left: 0,
    width: 320,
    borderRadius: '18px',
    border: '1px solid var(--border)',
    background: 'rgba(17,21,28,0.96)',
    boxShadow: '0 24px 60px rgba(0, 0, 0, 0.35)',
    overflow: 'hidden',
    zIndex: 30,
    backdropFilter: 'blur(14px) saturate(1.2)',
    WebkitBackdropFilter: 'blur(14px) saturate(1.2)',
  } as React.CSSProperties,
  projectMenuHeader: {
    padding: '12px',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  } as React.CSSProperties,
  projectMenuLabel: {
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.12em',
    color: 'var(--accent-bright)',
    fontWeight: 700,
  } as React.CSSProperties,
  projectSearch: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    borderRadius: '12px',
    border: '1px solid var(--border)',
    background: 'var(--bg-tertiary)',
    padding: '0 10px',
  } as React.CSSProperties,
  projectSearchInput: {
    width: '100%',
    border: 'none',
    outline: 'none',
    background: 'transparent',
    color: 'var(--text-primary)',
    padding: '10px 0',
    fontSize: '12px',
  } as React.CSSProperties,
  projectMenuList: {
    maxHeight: 280,
    overflowY: 'auto',
    padding: '8px',
  } as React.CSSProperties,
  projectMenuItem: {
    width: '100%',
    border: 'none',
    background: 'transparent',
    borderRadius: '12px',
    padding: '10px 12px',
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    cursor: 'pointer',
    color: 'var(--text-secondary)',
    transition: 'all var(--transition-fast)',
    textAlign: 'left',
  } as React.CSSProperties,
  projectMenuItemMeta: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  projectEmpty: {
    padding: '16px',
    fontSize: '12px',
    color: 'var(--text-muted)',
  } as React.CSSProperties,
  lang: {
    fontSize: '10px',
    padding: '2px 8px',
    borderRadius: '10px',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    fontWeight: 500,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    border: '1px solid var(--border)',
  } as React.CSSProperties,
  metaChip: {
    fontSize: '10px',
    padding: '2px 8px',
    borderRadius: '10px',
    background: 'rgba(255,255,255,0.04)',
    color: 'var(--text-muted)',
    border: '1px solid var(--border-subtle)',
    fontFamily: 'var(--font-mono)',
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
    gap: '10px',
    fontSize: '11px',
    color: 'var(--text-secondary)',
    animation: 'unweaver-fade-in 0.3s ease',
  } as React.CSSProperties,
  progressBar: {
    width: 120,
    height: 5,
    background: 'var(--bg-tertiary)',
    borderRadius: 3,
    overflow: 'hidden',
    border: '1px solid var(--border)',
  } as React.CSSProperties,
  progressFill: {
    height: '100%',
    background: 'linear-gradient(90deg, var(--accent) 0%, var(--accent-bright) 100%)',
    borderRadius: 3,
    transition: 'width 0.5s ease',
    position: 'relative',
    overflow: 'hidden',
  } as React.CSSProperties,
  iterLabel: {
    fontFamily: 'var(--font-mono)',
    fontSize: '10px',
    fontWeight: 600,
    color: 'var(--accent)',
    letterSpacing: '0.02em',
  } as React.CSSProperties,
  btn: {
    padding: '6px 14px',
    fontSize: '11px',
    fontWeight: 600,
    borderRadius: 'var(--radius-md)',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    cursor: 'pointer',
    transition: 'all var(--transition-med)',
    border: 'none',
  } as React.CSSProperties,
  analyseBtn: {
    background: 'linear-gradient(135deg, #2563eb 0%, #3b82f6 50%, #60a5fa 100%)',
    color: '#fff',
    boxShadow: '0 2px 8px rgba(37,99,235,0.3)',
  } as React.CSSProperties,
  analyseBtnHover: {
    boxShadow: '0 4px 16px rgba(37,99,235,0.45)',
    transform: 'translateY(-1px)',
  } as React.CSSProperties,
  stopBtn: {
    background: 'var(--danger-muted)',
    color: 'var(--danger)',
    border: '1px solid rgba(248,81,73,0.3)',
  } as React.CSSProperties,
  iconBtn: {
    padding: '7px',
    borderRadius: 'var(--radius-md)',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    transition: 'all var(--transition-fast)',
  } as React.CSSProperties,
  actionInfo: {
    fontSize: '11px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
    maxWidth: '200px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  } as React.CSSProperties,
  downloadBtn: {
    background: 'var(--success-muted)',
    color: 'var(--success)',
    border: '1px solid rgba(63,185,80,0.3)',
  } as React.CSSProperties,
  emptyBar: {
    height: 52,
    minHeight: 52,
    background: 'rgba(17,21,28,0.75)',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    alignItems: 'center',
    padding: '0 16px',
    backdropFilter: 'blur(12px) saturate(1.2)',
    WebkitBackdropFilter: 'blur(12px) saturate(1.2)',
  } as React.CSSProperties,
};

export default function TopBar({
  projects,
  selectedProjectId,
  onSelectProject,
  sample,
  analysisStatus,
  onStartAnalysis,
  onStopAnalysis,
  onRefresh,
}: TopBarProps) {
  const [exporting, setExporting] = useState(false);
  const [analyseHover, setAnalyseHover] = useState(false);
  const [projectMenuOpen, setProjectMenuOpen] = useState(false);
  const [projectQuery, setProjectQuery] = useState('');
  const projectMenuRef = useRef<HTMLDivElement | null>(null);

  const isRunning = sample?.status === 'running';
  const isPending = sample?.status === 'pending';
  const canStart = sample && !isRunning && !isPending;
  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedProjectId) ?? null,
    [projects, selectedProjectId],
  );
  const filteredProjects = useMemo(() => {
    const query = projectQuery.trim().toLowerCase();
    if (!query) return projects;
    return projects.filter((project) => project.name.toLowerCase().includes(query));
  }, [projects, projectQuery]);

  useEffect(() => {
    if (!projectMenuOpen) return;
    const handlePointerDown = (event: MouseEvent) => {
      if (!projectMenuRef.current?.contains(event.target as Node)) {
        setProjectMenuOpen(false);
      }
    };
    window.addEventListener('mousedown', handlePointerDown);
    return () => window.removeEventListener('mousedown', handlePointerDown);
  }, [projectMenuOpen]);

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

  const handleDownloadDeobfuscated = useCallback(async () => {
    if (!sample) return;
    setExporting(true);
    try {
      const { blob, filename } = await api.exportDeobfuscated(sample.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename ?? `deobfuscated_${sample.filename}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download failed:', err);
    } finally {
      setExporting(false);
    }
  }, [sample]);

  const handleSelectProjectFromMenu = useCallback((id: string) => {
    onSelectProject(id);
    setProjectMenuOpen(false);
    setProjectQuery('');
  }, [onSelectProject]);

  const projectSwitcher = (
    <div style={s.projectSwitcher} ref={projectMenuRef}>
      <button
        type="button"
        style={s.projectButton}
        onClick={() => setProjectMenuOpen((open) => !open)}
        onMouseEnter={(e) => {
          e.currentTarget.style.borderColor = 'var(--accent-border)';
          e.currentTarget.style.background = 'var(--accent-muted)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.borderColor = 'var(--border)';
          e.currentTarget.style.background = 'rgba(255,255,255,0.04)';
        }}
      >
        <FolderOpen size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />
        <span style={s.projectButtonText}>
          {selectedProject?.name ?? 'Switch Project'}
        </span>
        <ChevronDown
          size={12}
          style={{
            color: 'var(--text-muted)',
            flexShrink: 0,
            transform: projectMenuOpen ? 'rotate(180deg)' : 'none',
            transition: 'transform 0.2s ease',
          }}
        />
      </button>
      {projectMenuOpen && (
        <div style={s.projectMenu}>
          <div style={s.projectMenuHeader}>
            <div style={s.projectMenuLabel}>Project Switcher</div>
            <div style={s.projectSearch}>
              <Search size={13} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
              <input
                style={s.projectSearchInput}
                value={projectQuery}
                onChange={(e) => setProjectQuery(e.target.value)}
                placeholder="Search projects..."
                autoFocus
              />
            </div>
          </div>
          <div style={s.projectMenuList}>
            {filteredProjects.length > 0 ? (
              filteredProjects.map((project) => {
                const active = project.id === selectedProjectId;
                return (
                  <button
                    key={project.id}
                    type="button"
                    style={{
                      ...s.projectMenuItem,
                      ...(active ? { background: 'var(--accent-muted)', color: 'var(--text-primary)' } : {}),
                    }}
                    onClick={() => handleSelectProjectFromMenu(project.id)}
                    onMouseEnter={(e) => {
                      if (!active) {
                        e.currentTarget.style.background = 'var(--bg-hover)';
                        e.currentTarget.style.color = 'var(--text-primary)';
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!active) {
                        e.currentTarget.style.background = 'transparent';
                        e.currentTarget.style.color = 'var(--text-secondary)';
                      }
                    }}
                  >
                    <FolderOpen size={13} style={{ color: active ? 'var(--accent)' : 'var(--text-muted)', flexShrink: 0 }} />
                    <span style={{ flex: 1, minWidth: 0 }}>
                      <span style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '12px', fontWeight: 600 }}>
                        {project.name}
                      </span>
                      <span style={s.projectMenuItemMeta}>
                        {active ? 'Current project' : 'Open project'}
                      </span>
                    </span>
                  </button>
                );
              })
            ) : (
              <div style={s.projectEmpty}>No projects match that search.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );

  if (!sample) {
    return (
      <div className="unweaver-glass-bar" style={s.emptyBar}>
        {projectSwitcher}
        <div style={s.separator} />
        <span style={{ color: 'var(--text-muted)', fontSize: '12px', fontStyle: 'italic' }}>
          {selectedProject ? 'Select a sample to begin' : 'Select or create a project to begin'}
        </span>
      </div>
    );
  }

  const languageLabel = sample.language === 'workspace' ? 'bundle' : sample.language;
  const parsedWorkspace = sample.language === 'workspace'
    ? parseWorkspaceBundle(sample.recovered_text ?? '') ?? parseWorkspaceBundle(sample.original_text)
    : null;
  const workspaceFileCount = sample.saved_analysis?.workspace_context?.included_files ?? parsedWorkspace?.included_files;

  return (
    <div className="unweaver-glass-bar" style={s.root}>
      {projectSwitcher}
      <div style={s.separator} />
      <span style={s.title}>{sample.filename}</span>
      {languageLabel && <span style={s.lang}>{languageLabel}</span>}
      {sample.language === 'workspace' && typeof workspaceFileCount === 'number' && (
        <span style={s.metaChip}>{workspaceFileCount} files</span>
      )}
      {sample.saved_analysis_at && (
        <span style={s.metaChip}>saved report</span>
      )}
      <StatusBadge status={sample.status} />

      {/* Progress indicator during analysis */}
      {(isRunning || isPending) && analysisStatus && (
        <>
          <div style={s.separator} />
          <div style={s.progress}>
            <Loader2
              size={13}
              style={{
                animation: 'unweaver-spin 1s linear infinite',
                color: 'var(--accent)',
              }}
            />
            <div style={s.progressBar}>
              <div
                className="unweaver-progress-striped"
                style={{
                  ...s.progressFill,
                  width: `${Math.max(analysisStatus.progress_pct, 3)}%`,
                }}
              />
            </div>
            <span style={s.iterLabel}>
              {analysisStatus.current_iteration}/{analysisStatus.total_iterations || '?'}
            </span>
          </div>
          {analysisStatus.current_action && (
            <span style={s.actionInfo}>{analysisStatus.current_action}</span>
          )}
        </>
      )}

      <div style={s.spacer} />

      {/* Action buttons */}
      {isRunning || isPending ? (
        <button
          style={{ ...s.btn, ...s.stopBtn }}
          onClick={onStopAnalysis}
          onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(248,81,73,0.2)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = 'var(--danger-muted)'; }}
        >
          <Square size={12} />
          Stop
        </button>
      ) : (
        <button
          style={{
            ...s.btn,
            ...s.analyseBtn,
            ...(analyseHover && canStart ? s.analyseBtnHover : {}),
            ...(canStart && !analyseHover ? { animation: 'unweaver-glow-pulse 2.5s ease-in-out infinite' } : {}),
            opacity: canStart ? 1 : 0.35,
            cursor: canStart ? 'pointer' : 'default',
          }}
          onClick={canStart ? onStartAnalysis : undefined}
          onMouseEnter={() => setAnalyseHover(true)}
          onMouseLeave={() => setAnalyseHover(false)}
        >
          <Play size={12} />
          Analyse
          <span className="unweaver-kbd" style={{ marginLeft: '4px' }}>Ctrl+Enter</span>
        </button>
      )}

      <div style={s.separator} />

      <button
        style={s.iconBtn}
        onClick={onRefresh}
        title="Refresh"
        onMouseEnter={(e) => {
          e.currentTarget.style.color = 'var(--text-primary)';
          e.currentTarget.style.background = 'var(--bg-tertiary)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.color = 'var(--text-muted)';
          e.currentTarget.style.background = 'transparent';
        }}
      >
        <RefreshCw size={14} />
      </button>

      {sample.status === 'completed' && (
        <button
          style={{
            ...s.btn,
            ...s.downloadBtn,
            opacity: exporting ? 0.5 : 1,
          }}
          onClick={handleDownloadDeobfuscated}
          title="Download deobfuscated file"
          disabled={exporting}
          onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(63,185,80,0.2)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = 'var(--success-muted)'; }}
        >
          <FileCode size={12} />
          Download
        </button>
      )}

      <button
        style={{ ...s.iconBtn, opacity: exporting ? 0.5 : 1 }}
        onClick={handleExportMd}
        title="Export Markdown report"
        disabled={exporting}
        onMouseEnter={(e) => {
          e.currentTarget.style.color = 'var(--text-primary)';
          e.currentTarget.style.background = 'var(--bg-tertiary)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.color = 'var(--text-muted)';
          e.currentTarget.style.background = 'transparent';
        }}
      >
        <FileText size={14} />
      </button>
      <button
        style={{ ...s.iconBtn, opacity: exporting ? 0.5 : 1 }}
        onClick={handleExportJson}
        title="Export JSON report"
        disabled={exporting}
        onMouseEnter={(e) => {
          e.currentTarget.style.color = 'var(--text-primary)';
          e.currentTarget.style.background = 'var(--bg-tertiary)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.color = 'var(--text-muted)';
          e.currentTarget.style.background = 'transparent';
        }}
      >
        <Download size={14} />
      </button>
    </div>
  );
}
