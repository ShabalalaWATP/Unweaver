import { useState, useCallback, useRef } from 'react';
import { FolderPlus, Upload, ClipboardPaste, Settings, ChevronRight, File, Folder, Sparkles, Trash2, Sun, Moon } from 'lucide-react';
import { useProjects, useSamples } from '@/hooks/useApi';
import { useToast } from '@/components/common/Toast';
import { useTheme } from '@/contexts/ThemeContext';
import FileUpload from '@/components/common/FileUpload';
import PasteInput from '@/components/common/PasteInput';
import { formatDate, truncate } from '@/utils/format';
import controlRailGraphic from '@/assets/graphics/control-rail.svg';

interface SidebarProps {
  selectedProjectId: string | null;
  selectedSampleId: string | null;
  onSelectProject: (id: string) => void;
  onSelectSample: (id: string) => void;
  onOpenSettings: () => void;
  onDeleteProject?: (id: string) => void;
  onDeleteSample?: (id: string) => void;
}

type WorkspaceArchiveFile = File & {
  unweaverUploadKind?: 'folder-archive';
  unweaverSourceName?: string;
  unweaverSourceFileCount?: number;
};

const s = {
  root: {
    width: 260,
    minWidth: 260,
    background: 'var(--bg-secondary)',
    borderRight: '1px solid var(--border)',
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    overflow: 'hidden',
    position: 'relative',
  } as React.CSSProperties,
  ambientGraphic: {
    position: 'absolute',
    top: 72,
    left: -68,
    width: 360,
    opacity: 0.18,
    pointerEvents: 'none',
    mixBlendMode: 'screen',
    filter: 'saturate(1.1)',
  } as React.CSSProperties,
  header: {
    padding: '16px 16px 14px',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'stretch',
    gap: '12px',
    userSelect: 'none',
    background: 'rgba(17,21,28,0.6)',
    backdropFilter: 'blur(16px) saturate(1.3)',
    WebkitBackdropFilter: 'blur(16px) saturate(1.3)',
    position: 'relative',
    zIndex: 1,
  } as React.CSSProperties,
  brandRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
  } as React.CSSProperties,
  logoMark: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: 28,
    height: 28,
    borderRadius: 'var(--radius-md)',
    background: 'linear-gradient(135deg, var(--accent-muted) 0%, rgba(88,166,255,0.08) 100%)',
    border: '1px solid rgba(88,166,255,0.2)',
    color: 'var(--accent)',
    flexShrink: 0,
  } as React.CSSProperties,
  logoText: {
    fontWeight: 700,
    fontSize: '13px',
    letterSpacing: '0.1em',
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  logoVersion: {
    fontSize: '9px',
    fontWeight: 500,
    color: 'var(--text-muted)',
    marginLeft: 'auto',
    letterSpacing: '0.03em',
  } as React.CSSProperties,
  brandMeta: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
    minWidth: 0,
  } as React.CSSProperties,
  brandSubline: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
  } as React.CSSProperties,
  brandPanel: {
    padding: '12px',
    borderRadius: '18px',
    background: 'linear-gradient(165deg, rgba(88,166,255,0.12) 0%, rgba(17,21,28,0.58) 100%)',
    border: '1px solid rgba(88,166,255,0.14)',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  } as React.CSSProperties,
  brandPanelTitle: {
    fontSize: '14px',
    fontWeight: 700,
    lineHeight: 1.15,
    color: 'var(--text-primary)',
    maxWidth: '16ch',
  } as React.CSSProperties,
  brandPanelBody: {
    fontSize: '11px',
    lineHeight: 1.5,
    color: 'var(--text-secondary)',
    maxWidth: '20ch',
  } as React.CSSProperties,
  brandPanelStrip: {
    display: 'flex',
    gap: '6px',
    flexWrap: 'wrap',
  } as React.CSSProperties,
  brandPanelChip: {
    padding: '3px 8px',
    borderRadius: '999px',
    border: '1px solid rgba(255,255,255,0.08)',
    background: 'rgba(255,255,255,0.04)',
    color: 'var(--text-secondary)',
    fontSize: '10px',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  section: {
    padding: '10px 0 6px',
    borderBottom: '1px solid var(--border)',
  } as React.CSSProperties,
  sectionHeader: {
    padding: '2px 16px 6px',
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.1em',
    color: 'var(--text-muted)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  } as React.CSSProperties,
  list: {
    flex: 1,
    overflowY: 'auto',
    padding: '2px 0',
  } as React.CSSProperties,
  item: {
    padding: '7px 12px 7px 16px',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '12px',
    color: 'var(--text-secondary)',
    transition: 'all 0.15s ease',
    userSelect: 'none',
    margin: '0 6px',
    borderRadius: 'var(--radius-sm)',
    position: 'relative',
    overflow: 'hidden',
  } as React.CSSProperties,
  itemActive: {
    background: 'var(--accent-muted)',
    color: 'var(--text-primary)',
  } as React.CSSProperties,
  iconBtn: {
    padding: '3px',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    transition: 'all var(--transition-fast)',
  } as React.CSSProperties,
  deleteBtn: {
    padding: '3px',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    transition: 'all 0.15s',
    opacity: 0,
    marginLeft: 'auto',
    flexShrink: 0,
  } as React.CSSProperties,
  actions: {
    padding: '6px 10px',
    display: 'flex',
    gap: '6px',
  } as React.CSSProperties,
  actionBtn: {
    flex: 1,
    padding: '7px 8px',
    fontSize: '11px',
    fontWeight: 500,
    borderRadius: 'var(--radius-md)',
    border: '1px solid var(--border)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '5px',
    cursor: 'pointer',
    transition: 'all var(--transition-med)',
  } as React.CSSProperties,
  footer: {
    marginTop: 'auto',
    padding: '10px 12px',
    borderTop: '1px solid var(--border)',
  } as React.CSSProperties,
  settingsBtn: {
    width: '100%',
    padding: '8px 12px',
    fontSize: '12px',
    color: 'var(--text-muted)',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    borderRadius: 'var(--radius-md)',
    cursor: 'pointer',
    transition: 'all var(--transition-fast)',
  } as React.CSSProperties,
  newProjectRow: {
    padding: '4px 10px',
    display: 'flex',
    gap: '4px',
  } as React.CSSProperties,
  input: {
    flex: 1,
    padding: '5px 8px',
    fontSize: '12px',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    outline: 'none',
  } as React.CSSProperties,
  createBtn: {
    padding: '5px 12px',
    fontSize: '11px',
    background: 'var(--accent-muted)',
    color: 'var(--accent)',
    borderRadius: 'var(--radius-sm)',
    border: '1px solid rgba(88,166,255,0.3)',
    cursor: 'pointer',
    fontWeight: 600,
    transition: 'all var(--transition-fast)',
  } as React.CSSProperties,
  statusDot: {
    width: 7,
    height: 7,
    borderRadius: '50%',
    flexShrink: 0,
    boxShadow: '0 0 6px currentColor',
  } as React.CSSProperties,
  sampleMeta: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  dropOverlay: {
    position: 'absolute',
    inset: 0,
    background: 'rgba(88,166,255,0.08)',
    border: '2px dashed var(--accent)',
    borderRadius: 'var(--radius-md)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '12px',
    fontWeight: 600,
    color: 'var(--accent)',
    zIndex: 10,
    pointerEvents: 'none',
    backdropFilter: 'blur(2px)',
  } as React.CSSProperties,
};

const statusColors: Record<string, string> = {
  ready: 'var(--warning)',
  pending: 'var(--text-muted)',
  running: 'var(--accent)',
  completed: 'var(--success)',
  failed: 'var(--danger)',
  stopped: 'var(--warning)',
};

function isWorkspaceArchiveFile(file: File): file is WorkspaceArchiveFile {
  return (file as WorkspaceArchiveFile).unweaverUploadKind === 'folder-archive';
}

export default function Sidebar({
  selectedProjectId,
  selectedSampleId,
  onSelectProject,
  onSelectSample,
  onOpenSettings,
  onDeleteProject,
  onDeleteSample,
}: SidebarProps) {
  const { projects, create, remove: removeProject } = useProjects();
  const { samples, upload, paste, remove: removeSample } = useSamples(selectedProjectId);
  const { toggleTheme, isDark } = useTheme();
  const [showNewProject, setShowNewProject] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [showUpload, setShowUpload] = useState(false);
  const [showPaste, setShowPaste] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<{ type: 'project' | 'sample'; id: string } | null>(null);
  const dragCounter = useRef(0);
  const toast = useToast();

  const handleCreate = useCallback(async () => {
    if (!newProjectName.trim()) return;
    try {
      const p = await create(newProjectName.trim());
      setNewProjectName('');
      setShowNewProject(false);
      onSelectProject(p.id);
      toast.success(`Project "${p.name}" created`);
    } catch (err) {
      toast.error('Failed to create project');
    }
  }, [newProjectName, create, onSelectProject, toast]);

  const handleUpload = useCallback(
    async (files: File[]) => {
      const uploadedSamples = [];
      const failedFiles: string[] = [];

      for (const file of files) {
        try {
          const sample = await upload(file);
          uploadedSamples.push(sample);
        } catch (err) {
          failedFiles.push(file.name);
        }
      }

      if (uploadedSamples.length > 0) {
        setShowUpload(false);
        onSelectSample(uploadedSamples[uploadedSamples.length - 1].id);
      }

      if (failedFiles.length === 0 && uploadedSamples.length > 0) {
        if (uploadedSamples.length === 1) {
          if (isWorkspaceArchiveFile(files[0])) {
            toast.success(
              `Uploaded ${files[0].unweaverSourceName} as a codebase bundle. Open the workspace tabs to browse the bundled files.`,
            );
          } else {
            toast.success(`Uploaded "${files[0].name}"`);
          }
        } else {
          toast.success(`Uploaded ${uploadedSamples.length} items`);
        }
        return;
      }

      if (uploadedSamples.length > 0) {
        toast.warning(`Uploaded ${uploadedSamples.length} item(s), failed ${failedFiles.length}.`);
        return;
      }

      toast.error(files.length === 1 ? `Failed to upload "${files[0].name}"` : 'Failed to upload selected files');
      throw new Error(
        failedFiles.length > 0
          ? `Upload failed for: ${failedFiles.slice(0, 4).join(', ')}`
          : 'Upload failed. Please try again.',
      );
    },
    [upload, onSelectSample, toast],
  );

  const handlePaste = useCallback(
    async (text: string, filename?: string, language?: string) => {
      try {
        const sample = await paste(text, filename, language);
        setShowPaste(false);
        onSelectSample(sample.id);
        toast.success('Code pasted successfully');
      } catch (err) {
        toast.error('Failed to paste code');
      }
    },
    [paste, onSelectSample, toast],
  );

  const handleDeleteProject = useCallback(
    async (id: string) => {
      try {
        await removeProject(id);
        onDeleteProject?.(id);
        setConfirmDelete(null);
        toast.success('Project deleted');
      } catch (err) {
        toast.error('Failed to delete project');
      }
    },
    [removeProject, onDeleteProject, toast],
  );

  const handleDeleteSample = useCallback(
    async (id: string) => {
      try {
        await removeSample(id);
        onDeleteSample?.(id);
        setConfirmDelete(null);
        toast.success('Sample deleted');
      } catch (err) {
        toast.error('Failed to delete sample');
      }
    },
    [removeSample, onDeleteSample, toast],
  );

  // ── Drag-and-drop handlers ──────────────────────────────────────
  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current++;
    if (e.dataTransfer.types.includes('Files')) {
      setDragOver(true);
    }
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current--;
    if (dragCounter.current === 0) {
      setDragOver(false);
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDragOver(false);
      dragCounter.current = 0;

      if (!selectedProjectId) {
        toast.warning('Select a project first to upload files or archives');
        return;
      }

      const files = Array.from(e.dataTransfer.files);
      if (files.length === 0) return;

      for (const file of files) {
        try {
          const sample = await upload(file);
          onSelectSample(sample.id);
          toast.success(`Uploaded "${file.name}"`);
        } catch (err) {
          toast.error(`Failed to upload "${file.name}"`);
        }
      }
    },
    [selectedProjectId, upload, onSelectSample, toast],
  );

  return (
    <div
      style={s.root}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      <img
        className="unweaver-sidebar-atlas"
        src={controlRailGraphic}
        alt="Decorative control rail"
        style={s.ambientGraphic}
      />
      {/* Drag overlay */}
      {dragOver && (
        <div style={s.dropOverlay as React.CSSProperties}>
          <Upload size={16} style={{ marginRight: '6px' }} />
          Drop files or archives to upload
        </div>
      )}

      {/* Logo header */}
      <div className="unweaver-glass-header" style={s.header}>
        <div style={s.brandRow}>
          <div style={s.logoMark}>
            <Sparkles size={14} />
          </div>
          <div style={s.brandMeta}>
            <span style={s.logoText}>UNWEAVER</span>
            <span style={s.brandSubline}>Obfuscated code deobfuscation</span>
          </div>
          <span style={s.logoVersion}>v1.0</span>
        </div>
        <div className="unweaver-sidebar-brand-panel" style={s.brandPanel}>
          <div style={s.brandPanelTitle}>Professional deobfuscation workspace.</div>
          <div style={s.brandPanelBody}>
            Intake suspicious scripts, inspect transform history, and export reconstructed code with analyst-grade context.
          </div>
          <div style={s.brandPanelStrip}>
            <span style={s.brandPanelChip}>files</span>
            <span style={s.brandPanelChip}>folders</span>
            <span style={s.brandPanelChip}>workspace bundles</span>
          </div>
        </div>
      </div>

      {/* Projects */}
      <div style={s.section}>
        <div style={s.sectionHeader}>
          <span>Projects</span>
          <button
            style={s.iconBtn}
            onClick={() => setShowNewProject(!showNewProject)}
            title="New project"
            onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--accent)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-muted)'; }}
          >
            <FolderPlus size={13} />
          </button>
        </div>
        {showNewProject && (
          <div style={s.newProjectRow}>
            <input
              style={s.input}
              placeholder="Project name..."
              value={newProjectName}
              onChange={(e) => setNewProjectName(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
              autoFocus
            />
            <button style={s.createBtn} onClick={handleCreate}>
              Add
            </button>
          </div>
        )}
        <div style={s.list}>
          {projects.map((p) => (
            <div
              key={p.id}
              className={`unweaver-nav-item${selectedProjectId === p.id ? ' unweaver-nav-item--active' : ''}`}
              style={{
                ...s.item,
                ...(selectedProjectId === p.id ? s.itemActive : {}),
              }}
              onClick={() => onSelectProject(p.id)}
              onMouseEnter={(e) => {
                if (selectedProjectId !== p.id) {
                  e.currentTarget.style.background = 'var(--bg-hover)';
                  e.currentTarget.style.color = 'var(--text-primary)';
                }
                // Show delete button
                const delBtn = e.currentTarget.querySelector('[data-delete-btn]') as HTMLElement;
                if (delBtn) delBtn.style.opacity = '1';
              }}
              onMouseLeave={(e) => {
                if (selectedProjectId !== p.id) {
                  e.currentTarget.style.background = 'transparent';
                  e.currentTarget.style.color = 'var(--text-secondary)';
                }
                const delBtn = e.currentTarget.querySelector('[data-delete-btn]') as HTMLElement;
                if (delBtn) delBtn.style.opacity = '0';
              }}
            >
              <Folder
                size={13}
                style={{
                  opacity: selectedProjectId === p.id ? 0.9 : 0.4,
                  color: selectedProjectId === p.id ? 'var(--accent)' : 'inherit',
                  flexShrink: 0,
                }}
              />
              <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {truncate(p.name, 22)}
              </span>
              {confirmDelete?.type === 'project' && confirmDelete.id === p.id ? (
                <span style={{ display: 'flex', gap: '4px', marginLeft: 'auto', flexShrink: 0 }}>
                  <button
                    style={{ ...s.iconBtn, color: 'var(--danger)', fontSize: '10px', fontWeight: 600, padding: '1px 4px' }}
                    onClick={(e) => { e.stopPropagation(); handleDeleteProject(p.id); }}
                  >
                    Yes
                  </button>
                  <button
                    style={{ ...s.iconBtn, color: 'var(--text-muted)', fontSize: '10px', fontWeight: 600, padding: '1px 4px' }}
                    onClick={(e) => { e.stopPropagation(); setConfirmDelete(null); }}
                  >
                    No
                  </button>
                </span>
              ) : (
                <>
                  <button
                    data-delete-btn
                    style={s.deleteBtn}
                    title="Delete project"
                    onClick={(e) => {
                      e.stopPropagation();
                      setConfirmDelete({ type: 'project', id: p.id });
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--danger)'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-muted)'; }}
                  >
                    <Trash2 size={11} />
                  </button>
                  <ChevronRight
                    size={10}
                    style={{
                      transform: selectedProjectId === p.id ? 'rotate(90deg)' : 'none',
                      transition: 'transform 0.2s ease',
                      opacity: 0.3,
                      flexShrink: 0,
                    }}
                  />
                </>
              )}
            </div>
          ))}
          {projects.length === 0 && (
            <div style={{ ...s.item, color: 'var(--text-muted)', cursor: 'default', opacity: 0.6 }}>
              No projects yet
            </div>
          )}
        </div>
      </div>

      {/* Samples */}
      {selectedProjectId && (
        <div style={{ ...s.section, flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative' }}>
          <div style={s.sectionHeader}>
            <span>Samples</span>
          </div>
          <div style={s.actions}>
            <button
              style={s.actionBtn}
              onClick={() => setShowUpload(true)}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--accent)';
                e.currentTarget.style.color = 'var(--accent)';
                e.currentTarget.style.background = 'var(--accent-muted)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border)';
                e.currentTarget.style.color = 'var(--text-secondary)';
                e.currentTarget.style.background = 'var(--bg-tertiary)';
              }}
            >
              <Upload size={12} />
              Upload
              <span className="unweaver-kbd">U</span>
            </button>
            <button
              style={s.actionBtn}
              onClick={() => setShowPaste(true)}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--accent)';
                e.currentTarget.style.color = 'var(--accent)';
                e.currentTarget.style.background = 'var(--accent-muted)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border)';
                e.currentTarget.style.color = 'var(--text-secondary)';
                e.currentTarget.style.background = 'var(--bg-tertiary)';
              }}
            >
              <ClipboardPaste size={12} />
              Paste
              <span className="unweaver-kbd">P</span>
            </button>
          </div>
          <div style={{ ...s.list, flex: 1 }}>
            {samples.map((sm) => (
              <div
                key={sm.id}
                className={`unweaver-nav-item${selectedSampleId === sm.id ? ' unweaver-nav-item--active' : ''}`}
                style={{
                  ...s.item,
                  ...(selectedSampleId === sm.id ? s.itemActive : {}),
                }}
                onClick={() => onSelectSample(sm.id)}
                onMouseEnter={(e) => {
                  if (selectedSampleId !== sm.id) {
                    e.currentTarget.style.background = 'var(--bg-hover)';
                    e.currentTarget.style.color = 'var(--text-primary)';
                  }
                  const delBtn = e.currentTarget.querySelector('[data-delete-btn]') as HTMLElement;
                  if (delBtn) delBtn.style.opacity = '1';
                }}
                onMouseLeave={(e) => {
                  if (selectedSampleId !== sm.id) {
                    e.currentTarget.style.background = 'transparent';
                    e.currentTarget.style.color = 'var(--text-secondary)';
                  }
                  const delBtn = e.currentTarget.querySelector('[data-delete-btn]') as HTMLElement;
                  if (delBtn) delBtn.style.opacity = '0';
                }}
              >
                <div
                  className={sm.status === 'running' ? 'unweaver-dot-ripple' : undefined}
                  style={{
                    ...s.statusDot,
                    color: statusColors[sm.status] ?? 'var(--text-muted)',
                    background: statusColors[sm.status] ?? 'var(--text-muted)',
                    animation: sm.status === 'running' ? 'unweaver-pulse 1.5s ease-in-out infinite' : 'none',
                  }}
                />
                <File size={12} style={{ opacity: 0.4, flexShrink: 0 }} />
                <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {sm.filename}
                </span>
                {confirmDelete?.type === 'sample' && confirmDelete.id === sm.id ? (
                  <span style={{ display: 'flex', gap: '4px', flexShrink: 0 }}>
                    <button
                      style={{ ...s.iconBtn, color: 'var(--danger)', fontSize: '10px', fontWeight: 600, padding: '1px 4px' }}
                      onClick={(e) => { e.stopPropagation(); handleDeleteSample(sm.id); }}
                    >
                      Yes
                    </button>
                    <button
                      style={{ ...s.iconBtn, color: 'var(--text-muted)', fontSize: '10px', fontWeight: 600, padding: '1px 4px' }}
                      onClick={(e) => { e.stopPropagation(); setConfirmDelete(null); }}
                    >
                      No
                    </button>
                  </span>
                ) : (
                  <>
                    <button
                      data-delete-btn
                      style={s.deleteBtn}
                      title="Delete sample"
                      onClick={(e) => {
                        e.stopPropagation();
                        setConfirmDelete({ type: 'sample', id: sm.id });
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--danger)'; }}
                      onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-muted)'; }}
                    >
                      <Trash2 size={11} />
                    </button>
                    <span style={s.sampleMeta}>
                      {sm.language === 'workspace' ? 'bundle' : formatDate(sm.created_at).split(',')[0]}
                      {sm.saved_analysis_at ? ' · saved' : ''}
                    </span>
                  </>
                )}
              </div>
            ))}
            {samples.length === 0 && (
              <div style={{ ...s.item, color: 'var(--text-muted)', cursor: 'default', opacity: 0.6 }}>
                {dragOver ? 'Drop files or archives here' : 'No samples'}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Upload / Paste modals */}
      {showUpload && (
        <FileUpload
          onUpload={handleUpload}
          onClose={() => setShowUpload(false)}
        />
      )}
      {showPaste && (
        <PasteInput
          onSubmit={handlePaste}
          onClose={() => setShowPaste(false)}
        />
      )}

      {/* Footer: Settings + Theme toggle */}
      <div style={s.footer}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <button
            style={{ ...s.settingsBtn, flex: 1 }}
            onClick={onOpenSettings}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = 'var(--bg-tertiary)';
              e.currentTarget.style.color = 'var(--text-primary)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent';
              e.currentTarget.style.color = 'var(--text-muted)';
            }}
          >
            <Settings size={14} style={{ opacity: 0.7 }} />
            Settings
          </button>
          <button
            onClick={toggleTheme}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            style={{
              padding: '8px',
              borderRadius: 'var(--radius-md)',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'transparent',
              border: 'none',
              flexShrink: 0,
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = 'var(--bg-tertiary)';
              e.currentTarget.style.color = isDark ? 'var(--warning)' : 'var(--accent)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent';
              e.currentTarget.style.color = 'var(--text-muted)';
            }}
          >
            {isDark ? <Sun size={15} /> : <Moon size={15} />}
          </button>
        </div>
      </div>
    </div>
  );
}
