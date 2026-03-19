import { useState, useCallback } from 'react';
import { FolderPlus, Upload, ClipboardPaste, Settings, ChevronRight, File } from 'lucide-react';
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
    padding: '12px 16px',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontWeight: 700,
    fontSize: '14px',
    letterSpacing: '0.08em',
    color: 'var(--text-primary)',
    userSelect: 'none',
  } as React.CSSProperties,
  logo: {
    color: 'var(--accent)',
    fontFamily: 'var(--font-mono)',
    fontSize: '15px',
  } as React.CSSProperties,
  section: {
    padding: '8px 0',
    borderBottom: '1px solid var(--border)',
  } as React.CSSProperties,
  sectionHeader: {
    padding: '4px 16px',
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    color: 'var(--text-muted)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  } as React.CSSProperties,
  list: {
    flex: 1,
    overflowY: 'auto',
    padding: '4px 0',
  } as React.CSSProperties,
  item: {
    padding: '6px 16px',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '12px',
    color: 'var(--text-secondary)',
    transition: 'background 0.1s, color 0.1s',
    userSelect: 'none',
  } as React.CSSProperties,
  itemActive: {
    background: 'var(--bg-tertiary)',
    color: 'var(--text-primary)',
  } as React.CSSProperties,
  iconBtn: {
    padding: '2px',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
  } as React.CSSProperties,
  actions: {
    padding: '8px 12px',
    display: 'flex',
    gap: '6px',
  } as React.CSSProperties,
  actionBtn: {
    flex: 1,
    padding: '6px 8px',
    fontSize: '11px',
    fontWeight: 500,
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '4px',
    cursor: 'pointer',
    transition: 'border-color 0.15s, color 0.15s',
  } as React.CSSProperties,
  footer: {
    marginTop: 'auto',
    padding: '8px 12px',
    borderTop: '1px solid var(--border)',
  } as React.CSSProperties,
  settingsBtn: {
    width: '100%',
    padding: '8px 12px',
    fontSize: '12px',
    color: 'var(--text-secondary)',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
    transition: 'background 0.1s, color 0.1s',
  } as React.CSSProperties,
  newProjectRow: {
    padding: '4px 12px',
    display: 'flex',
    gap: '4px',
  } as React.CSSProperties,
  input: {
    flex: 1,
    padding: '4px 8px',
    fontSize: '12px',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    outline: 'none',
  } as React.CSSProperties,
  createBtn: {
    padding: '4px 10px',
    fontSize: '11px',
    background: 'var(--accent-muted)',
    color: 'var(--accent)',
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--accent)',
    cursor: 'pointer',
    fontWeight: 500,
  } as React.CSSProperties,
  statusDot: {
    width: 6,
    height: 6,
    borderRadius: '50%',
    flexShrink: 0,
  } as React.CSSProperties,
  sampleMeta: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    marginLeft: 'auto',
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
      const sample = await paste(text, filename, language);
      setShowPaste(false);
      onSelectSample(sample.id);
    },
    [paste, onSelectSample],
  );

  return (
    <div style={s.root}>
      <div style={s.header}>
        <span style={s.logo}>{'>'}_</span>
        UNWEAVER
      </div>

      {/* Projects */}
      <div style={s.section}>
        <div style={s.sectionHeader}>
          <span>Projects</span>
          <button
            style={s.iconBtn}
            onClick={() => setShowNewProject(!showNewProject)}
            title="New project"
          >
            <FolderPlus size={14} />
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
            >
              <ChevronRight
                size={12}
                style={{
                  transform: selectedProjectId === p.id ? 'rotate(90deg)' : 'none',
                  transition: 'transform 0.15s',
                  opacity: 0.5,
                }}
              />
              {truncate(p.name, 28)}
            </div>
          ))}
          {projects.length === 0 && (
            <div style={{ ...s.item, color: 'var(--text-muted)', cursor: 'default' }}>
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
                e.currentTarget.style.color = 'var(--text-primary)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border)';
                e.currentTarget.style.color = 'var(--text-secondary)';
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
                e.currentTarget.style.color = 'var(--text-primary)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border)';
                e.currentTarget.style.color = 'var(--text-secondary)';
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
              >
                <div
                  style={{
                    ...s.statusDot,
                    background: statusColors[sm.status] ?? 'var(--text-muted)',
                  }}
                />
                <File size={12} style={{ opacity: 0.5, flexShrink: 0 }} />
                <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {sm.filename}
                </span>
                <span style={s.sampleMeta}>{formatDate(sm.created_at).split(',')[0]}</span>
              </div>
            ))}
            {samples.length === 0 && (
              <div style={{ ...s.item, color: 'var(--text-muted)', cursor: 'default' }}>
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
            e.currentTarget.style.color = 'var(--text-secondary)';
          }}
        >
          <Settings size={14} />
          Provider Settings
        </button>
      </div>
    </div>
  );
}
