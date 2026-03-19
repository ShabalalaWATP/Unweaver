import { useState, useCallback } from 'react';
import { FolderPlus, Upload, ClipboardPaste, Settings, ChevronRight, File, Folder, Sparkles } from 'lucide-react';
import { useProjects, useSamples } from '@/hooks/useApi';
import FileUpload from '@/components/common/FileUpload';
import PasteInput from '@/components/common/PasteInput';
import { formatDate, truncate } from '@/utils/format';

interface SidebarProps {
  selectedProjectId: string | null;
  selectedSampleId: string | null;
  onSelectProject: (id: string) => void;
  onSelectSample: (id: string) => void;
  onOpenSettings: () => void;
}

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
  } as React.CSSProperties,
  header: {
    padding: '14px 16px',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    userSelect: 'none',
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
    transition: 'all 0.12s ease',
    userSelect: 'none',
    margin: '0 6px',
    borderRadius: 'var(--radius-sm)',
  } as React.CSSProperties,
  itemActive: {
    background: 'var(--accent-muted)',
    color: 'var(--text-primary)',
    borderLeft: 'none',
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
    marginLeft: 'auto',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
};

const statusColors: Record<string, string> = {
  pending: 'var(--text-muted)',
  running: 'var(--accent)',
  completed: 'var(--success)',
  failed: 'var(--danger)',
  stopped: 'var(--warning)',
};

export default function Sidebar({
  selectedProjectId,
  selectedSampleId,
  onSelectProject,
  onSelectSample,
  onOpenSettings,
}: SidebarProps) {
  const { projects, create } = useProjects();
  const { samples, upload, paste } = useSamples(selectedProjectId);
  const [showNewProject, setShowNewProject] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [showUpload, setShowUpload] = useState(false);
  const [showPaste, setShowPaste] = useState(false);

  const handleCreate = useCallback(async () => {
    if (!newProjectName.trim()) return;
    const p = await create(newProjectName.trim());
    setNewProjectName('');
    setShowNewProject(false);
    onSelectProject(p.id);
  }, [newProjectName, create, onSelectProject]);

  const handleUpload = useCallback(
    async (file: File) => {
      const sample = await upload(file);
      setShowUpload(false);
      onSelectSample(sample.id);
    },
    [upload, onSelectSample],
  );

  const handlePaste = useCallback(
    async (text: string, filename?: string, language?: string) => {
      try {
        const sample = await paste(text, filename, language);
        setShowPaste(false);
        onSelectSample(sample.id);
      } catch (err) {
        console.error('Paste failed:', err);
      }
    },
    [paste, onSelectSample],
  );

  return (
    <div style={s.root}>
      {/* Logo header */}
      <div style={s.header}>
        <div style={s.logoMark}>
          <Sparkles size={14} />
        </div>
        <span style={s.logoText}>UNWEAVER</span>
        <span style={s.logoVersion}>v1.0</span>
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
              }}
              onMouseLeave={(e) => {
                if (selectedProjectId !== p.id) {
                  e.currentTarget.style.background = 'transparent';
                  e.currentTarget.style.color = 'var(--text-secondary)';
                }
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
              {truncate(p.name, 26)}
              <ChevronRight
                size={10}
                style={{
                  marginLeft: 'auto',
                  transform: selectedProjectId === p.id ? 'rotate(90deg)' : 'none',
                  transition: 'transform 0.2s ease',
                  opacity: 0.3,
                }}
              />
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
        <div style={{ ...s.section, flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
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
            </button>
          </div>
          <div style={{ ...s.list, flex: 1 }}>
            {samples.map((sm) => (
              <div
                key={sm.id}
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
                }}
                onMouseLeave={(e) => {
                  if (selectedSampleId !== sm.id) {
                    e.currentTarget.style.background = 'transparent';
                    e.currentTarget.style.color = 'var(--text-secondary)';
                  }
                }}
              >
                <div
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
                <span style={s.sampleMeta}>{formatDate(sm.created_at).split(',')[0]}</span>
              </div>
            ))}
            {samples.length === 0 && (
              <div style={{ ...s.item, color: 'var(--text-muted)', cursor: 'default', opacity: 0.6 }}>
                No samples
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

      {/* Settings */}
      <div style={s.footer}>
        <button
          style={s.settingsBtn}
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
          Provider Settings
        </button>
      </div>
    </div>
  );
}
