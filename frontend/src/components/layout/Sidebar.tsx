import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { FolderPlus, Upload, ClipboardPaste, Settings, ChevronRight, File, Folder, Sparkles, Trash2, Sun, Moon, MoreHorizontal, AlertTriangle } from 'lucide-react';
import { useSamples } from '@/hooks/useApi';
import { useToast } from '@/components/common/Toast';
import { useTheme } from '@/contexts/ThemeContext';
import FileUpload from '@/components/common/FileUpload';
import PasteInput from '@/components/common/PasteInput';
import { formatDate, truncate } from '@/utils/format';
import controlRailGraphic from '@/assets/graphics/control-rail.svg';
import type { Project, SampleStatus } from '@/types';
import * as api from '@/services/api';

interface SidebarProps {
  projects: Project[];
  createProject: (name: string, description?: string) => Promise<Project>;
  removeProject: (id: string) => Promise<void>;
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

type ProjectSort = 'recent' | 'alpha' | 'samples';
type SampleFilter = 'all' | SampleStatus | 'saved';

type ProjectStats = {
  sampleCount: number;
  lastActivity: string | null;
  runningCount: number;
  savedCount: number;
};

const ARCHIVED_PROJECTS_KEY = 'unweaver-archived-projects';

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
  sectionControls: {
    padding: '0 12px 10px',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  } as React.CSSProperties,
  searchInput: {
    width: '100%',
    padding: '8px 10px',
    fontSize: '12px',
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: '12px',
    color: 'var(--text-primary)',
    outline: 'none',
  } as React.CSSProperties,
  segmentedRow: {
    display: 'flex',
    gap: '6px',
    flexWrap: 'wrap',
  } as React.CSSProperties,
  segmentedBtn: {
    padding: '5px 8px',
    fontSize: '10px',
    fontWeight: 600,
    borderRadius: '999px',
    border: '1px solid var(--border)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    transition: 'all 0.15s ease',
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
  menuBtn: {
    padding: '4px',
    borderRadius: '10px',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    transition: 'all 0.15s',
    flexShrink: 0,
    border: 'none',
    background: 'transparent',
  } as React.CSSProperties,
  rowActions: {
    marginLeft: 'auto',
    position: 'relative',
    display: 'flex',
    alignItems: 'center',
    flexShrink: 0,
  } as React.CSSProperties,
  actionMenu: {
    position: 'absolute',
    top: 'calc(100% + 6px)',
    right: 0,
    width: 168,
    padding: '6px',
    borderRadius: '14px',
    border: '1px solid var(--border)',
    background: 'rgba(17,21,28,0.96)',
    boxShadow: '0 20px 40px rgba(0, 0, 0, 0.32)',
    zIndex: 20,
    backdropFilter: 'blur(12px) saturate(1.2)',
    WebkitBackdropFilter: 'blur(12px) saturate(1.2)',
  } as React.CSSProperties,
  actionMenuItem: {
    width: '100%',
    padding: '9px 10px',
    borderRadius: '10px',
    border: 'none',
    background: 'transparent',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '12px',
    textAlign: 'left',
    transition: 'all 0.15s ease',
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
  projectMeta: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
    whiteSpace: 'nowrap',
    flexShrink: 0,
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
  confirmOverlay: {
    position: 'absolute',
    inset: 0,
    background: 'var(--overlay-bg)',
    backdropFilter: 'blur(6px)',
    WebkitBackdropFilter: 'blur(6px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 40,
    padding: '20px',
  } as React.CSSProperties,
  confirmModal: {
    width: '100%',
    maxWidth: 360,
    borderRadius: '22px',
    border: '1px solid var(--border)',
    background: 'rgba(17,21,28,0.98)',
    boxShadow: '0 28px 60px rgba(0, 0, 0, 0.35)',
    overflow: 'hidden',
  } as React.CSSProperties,
  confirmHeader: {
    padding: '16px 18px 12px',
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    borderBottom: '1px solid var(--border)',
  } as React.CSSProperties,
  confirmTitle: {
    fontSize: '14px',
    fontWeight: 700,
    color: 'var(--text-primary)',
  } as React.CSSProperties,
  confirmBody: {
    padding: '16px 18px',
    fontSize: '12px',
    lineHeight: '1.6',
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
  confirmActions: {
    padding: '0 18px 18px',
    display: 'flex',
    justifyContent: 'flex-end',
    gap: '8px',
  } as React.CSSProperties,
  confirmCancel: {
    padding: '8px 12px',
    borderRadius: '12px',
    border: '1px solid var(--border)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    fontSize: '12px',
    fontWeight: 600,
  } as React.CSSProperties,
  confirmDelete: {
    padding: '8px 12px',
    borderRadius: '12px',
    border: '1px solid rgba(248,81,73,0.28)',
    background: 'var(--danger-muted)',
    color: 'var(--danger)',
    cursor: 'pointer',
    fontSize: '12px',
    fontWeight: 700,
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

function loadArchivedProjectIds(): string[] {
  try {
    const raw = localStorage.getItem(ARCHIVED_PROJECTS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === 'string') : [];
  } catch {
    return [];
  }
}

function saveArchivedProjectIds(ids: string[]) {
  try {
    localStorage.setItem(ARCHIVED_PROJECTS_KEY, JSON.stringify(ids));
  } catch {
    // ignore storage errors
  }
}

export default function Sidebar({
  projects,
  createProject,
  removeProject,
  selectedProjectId,
  selectedSampleId,
  onSelectProject,
  onSelectSample,
  onOpenSettings,
  onDeleteProject,
  onDeleteSample,
}: SidebarProps) {
  const { samples, upload, paste, remove: removeSample } = useSamples(selectedProjectId);
  const { toggleTheme, isDark } = useTheme();
  const [showNewProject, setShowNewProject] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [showUpload, setShowUpload] = useState(false);
  const [showPaste, setShowPaste] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [openMenu, setOpenMenu] = useState<{ type: 'project' | 'sample'; id: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{ type: 'project' | 'sample'; id: string; label: string } | null>(null);
  const [projectSearch, setProjectSearch] = useState('');
  const [projectSort, setProjectSort] = useState<ProjectSort>('recent');
  const [showArchived, setShowArchived] = useState(false);
  const [sampleSearch, setSampleSearch] = useState('');
  const [sampleFilter, setSampleFilter] = useState<SampleFilter>('all');
  const [archivedProjectIds, setArchivedProjectIds] = useState<string[]>(() => loadArchivedProjectIds());
  const [projectStats, setProjectStats] = useState<Record<string, ProjectStats>>({});
  const dragCounter = useRef(0);
  const toast = useToast();

  const handleCreate = useCallback(async () => {
    if (!newProjectName.trim()) return;
    try {
      const p = await createProject(newProjectName.trim());
      setNewProjectName('');
      setShowNewProject(false);
      onSelectProject(p.id);
      toast.success(`Project "${p.name}" created`);
    } catch (err) {
      toast.error('Failed to create project');
    }
  }, [newProjectName, createProject, onSelectProject, toast]);

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
        setOpenMenu(null);
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
        setOpenMenu(null);
        setConfirmDelete(null);
        toast.success('Sample deleted');
      } catch (err) {
        toast.error('Failed to delete sample');
      }
    },
    [removeSample, onDeleteSample, toast],
  );

  useEffect(() => {
    saveArchivedProjectIds(archivedProjectIds);
  }, [archivedProjectIds]);

  useEffect(() => {
    let cancelled = false;

    const loadProjectStats = async () => {
      const entries = await Promise.all(
        projects.map(async (project) => {
          try {
            const projectSamples = await api.listSamples(project.id);
            const sortedDates = projectSamples
              .map((sample) => sample.updated_at ?? sample.created_at)
              .filter((value): value is string => Boolean(value))
              .sort((a, b) => new Date(b).getTime() - new Date(a).getTime());
            const stats: ProjectStats = {
              sampleCount: projectSamples.length,
              lastActivity: sortedDates[0] ?? null,
              runningCount: projectSamples.filter((sample) => sample.status === 'running' || sample.status === 'pending').length,
              savedCount: projectSamples.filter((sample) => Boolean(sample.saved_analysis_at)).length,
            };
            return [project.id, stats] as const;
          } catch {
            return [project.id, { sampleCount: 0, lastActivity: null, runningCount: 0, savedCount: 0 }] as const;
          }
        }),
      );

      if (!cancelled) {
        setProjectStats(Object.fromEntries(entries));
      }
    };

    if (projects.length === 0) {
      setProjectStats({});
      return undefined;
    }

    loadProjectStats().catch(() => {
      if (!cancelled) {
        setProjectStats({});
      }
    });

    return () => {
      cancelled = true;
    };
  }, [projects, samples]);

  const visibleProjects = useMemo(() => {
    const query = projectSearch.trim().toLowerCase();
    const filtered = projects
      .filter((project) => showArchived || !archivedProjectIds.includes(project.id))
      .filter((project) => (query ? project.name.toLowerCase().includes(query) : true));

    return [...filtered].sort((a, b) => {
      if (projectSort === 'alpha') {
        return a.name.localeCompare(b.name);
      }
      if (projectSort === 'samples') {
        const countDiff = (projectStats[b.id]?.sampleCount ?? 0) - (projectStats[a.id]?.sampleCount ?? 0);
        if (countDiff !== 0) return countDiff;
      }
      return new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime();
    });
  }, [archivedProjectIds, projectSearch, projectSort, projectStats, projects, showArchived]);

  const filteredSamples = useMemo(() => {
    const query = sampleSearch.trim().toLowerCase();
    return samples.filter((sample) => {
      const matchesQuery = !query
        || sample.filename.toLowerCase().includes(query)
        || (sample.language ?? '').toLowerCase().includes(query);
      if (!matchesQuery) return false;
      if (sampleFilter === 'all') return true;
      if (sampleFilter === 'saved') return Boolean(sample.saved_analysis_at);
      return sample.status === sampleFilter;
    });
  }, [sampleFilter, sampleSearch, samples]);

  const toggleArchiveProject = useCallback((projectId: string) => {
    const isArchived = archivedProjectIds.includes(projectId);
    if (!isArchived && selectedProjectId === projectId && !showArchived) {
      const nextProject = projects.find(
        (project) => project.id !== projectId && !archivedProjectIds.includes(project.id),
      );
      if (nextProject) {
        onSelectProject(nextProject.id);
      }
    }

    setArchivedProjectIds((current) => (
      current.includes(projectId)
        ? current.filter((id) => id !== projectId)
        : [...current, projectId]
    ));
    setOpenMenu(null);
  }, [archivedProjectIds, onSelectProject, projects, selectedProjectId, showArchived]);

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
      onClick={() => setOpenMenu(null)}
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
        <div style={s.sectionControls}>
          <input
            style={s.searchInput}
            value={projectSearch}
            onChange={(e) => setProjectSearch(e.target.value)}
            placeholder="Search projects..."
          />
          <div style={s.segmentedRow}>
            {([
              ['recent', 'Recent'],
              ['alpha', 'A-Z'],
              ['samples', 'Most samples'],
            ] as const).map(([value, label]) => (
              <button
                key={value}
                type="button"
                style={{
                  ...s.segmentedBtn,
                  ...(projectSort === value ? { background: 'var(--accent-muted)', color: 'var(--accent)', borderColor: 'var(--accent-border)' } : {}),
                }}
                onClick={() => setProjectSort(value)}
              >
                {label}
              </button>
            ))}
            <button
              type="button"
              style={{
                ...s.segmentedBtn,
                ...(showArchived ? { background: 'var(--warning-muted)', color: 'var(--warning)' } : {}),
              }}
              onClick={() => setShowArchived((value) => !value)}
            >
              {showArchived ? 'Hide archived' : 'Show archived'}
            </button>
          </div>
        </div>
        <div style={s.list}>
          {visibleProjects.map((p) => (
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
              <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {truncate(p.name, 22)}
              </span>
              <span style={s.projectMeta}>
                {projectStats[p.id]?.sampleCount ?? 0}
                {' '}samples
                {(projectStats[p.id]?.runningCount ?? 0) > 0 ? ` · ${projectStats[p.id]?.runningCount} live` : ''}
                {(projectStats[p.id]?.savedCount ?? 0) > 0 ? ` · ${projectStats[p.id]?.savedCount} saved` : ''}
              </span>
              <span style={s.rowActions}>
                <button
                  style={s.menuBtn}
                  title="Project actions"
                  onClick={(e) => {
                    e.stopPropagation();
                    setOpenMenu((current) => (
                      current?.type === 'project' && current.id === p.id
                        ? null
                        : { type: 'project', id: p.id }
                    ));
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.color = 'var(--text-primary)';
                    e.currentTarget.style.background = 'var(--bg-hover)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.color = 'var(--text-muted)';
                    e.currentTarget.style.background = 'transparent';
                  }}
                >
                  <MoreHorizontal size={13} />
                </button>
                {openMenu?.type === 'project' && openMenu.id === p.id && (
                  <div style={s.actionMenu} onClick={(e) => e.stopPropagation()}>
                    <button
                      style={s.actionMenuItem}
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleArchiveProject(p.id);
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.background = 'var(--bg-hover)';
                        e.currentTarget.style.color = 'var(--text-primary)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.background = 'transparent';
                        e.currentTarget.style.color = 'var(--text-secondary)';
                      }}
                    >
                      <Folder size={12} />
                      {archivedProjectIds.includes(p.id) ? 'Unarchive project' : 'Archive project'}
                    </button>
                    <button
                      style={s.actionMenuItem}
                      onClick={(e) => {
                        e.stopPropagation();
                        setConfirmDelete({ type: 'project', id: p.id, label: p.name });
                        setOpenMenu(null);
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.background = 'var(--danger-muted)';
                        e.currentTarget.style.color = 'var(--danger)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.background = 'transparent';
                        e.currentTarget.style.color = 'var(--text-secondary)';
                      }}
                    >
                      <Trash2 size={12} />
                      Delete project
                    </button>
                  </div>
                )}
              </span>
              <ChevronRight
                size={10}
                style={{
                  transform: selectedProjectId === p.id ? 'rotate(90deg)' : 'none',
                  transition: 'transform 0.2s ease',
                  opacity: 0.3,
                  flexShrink: 0,
                }}
              />
            </div>
          ))}
          {visibleProjects.length === 0 && (
            <div style={{ ...s.item, color: 'var(--text-muted)', cursor: 'default', opacity: 0.6 }}>
              {projects.length === 0 ? 'No projects yet' : 'No projects match the current filters'}
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
          <div style={s.sectionControls}>
            <input
              style={s.searchInput}
              value={sampleSearch}
              onChange={(e) => setSampleSearch(e.target.value)}
              placeholder="Search samples..."
            />
            <div style={s.segmentedRow}>
              {([
                ['all', 'All'],
                ['running', 'Running'],
                ['completed', 'Done'],
                ['failed', 'Failed'],
                ['saved', 'Saved'],
              ] as const).map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  style={{
                    ...s.segmentedBtn,
                    ...(sampleFilter === value ? { background: 'var(--accent-muted)', color: 'var(--accent)', borderColor: 'var(--accent-border)' } : {}),
                  }}
                  onClick={() => setSampleFilter(value)}
                >
                  {label}
                </button>
              ))}
            </div>
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
            {filteredSamples.map((sm) => (
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
                }}
                onMouseLeave={(e) => {
                  if (selectedSampleId !== sm.id) {
                    e.currentTarget.style.background = 'transparent';
                    e.currentTarget.style.color = 'var(--text-secondary)';
                  }
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
                <span style={s.sampleMeta}>
                  {sm.language === 'workspace' ? 'bundle' : formatDate(sm.created_at).split(',')[0]}
                  {sm.saved_analysis_at ? ' · saved' : ''}
                </span>
                <span style={s.rowActions}>
                  <button
                    style={s.menuBtn}
                    title="Sample actions"
                    onClick={(e) => {
                      e.stopPropagation();
                      setOpenMenu((current) => (
                        current?.type === 'sample' && current.id === sm.id
                          ? null
                          : { type: 'sample', id: sm.id }
                      ));
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.color = 'var(--text-primary)';
                      e.currentTarget.style.background = 'var(--bg-hover)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.color = 'var(--text-muted)';
                      e.currentTarget.style.background = 'transparent';
                    }}
                  >
                    <MoreHorizontal size={13} />
                  </button>
                  {openMenu?.type === 'sample' && openMenu.id === sm.id && (
                    <div style={s.actionMenu} onClick={(e) => e.stopPropagation()}>
                      <button
                        style={s.actionMenuItem}
                        onClick={(e) => {
                          e.stopPropagation();
                          setConfirmDelete({ type: 'sample', id: sm.id, label: sm.filename });
                          setOpenMenu(null);
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.background = 'var(--danger-muted)';
                          e.currentTarget.style.color = 'var(--danger)';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.background = 'transparent';
                          e.currentTarget.style.color = 'var(--text-secondary)';
                        }}
                      >
                        <Trash2 size={12} />
                        Delete sample
                      </button>
                    </div>
                  )}
                </span>
              </div>
            ))}
            {filteredSamples.length === 0 && (
              <div style={{ ...s.item, color: 'var(--text-muted)', cursor: 'default', opacity: 0.6 }}>
                {dragOver ? 'Drop files or archives here' : 'No samples match the current filters'}
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
      {confirmDelete && (
        <div style={s.confirmOverlay} onClick={() => setConfirmDelete(null)}>
          <div style={s.confirmModal} onClick={(e) => e.stopPropagation()}>
            <div style={s.confirmHeader}>
              <AlertTriangle size={16} color="var(--danger)" />
              <div style={s.confirmTitle}>
                Delete {confirmDelete.type === 'project' ? 'project' : 'sample'}?
              </div>
            </div>
            <div style={s.confirmBody}>
              <strong style={{ color: 'var(--text-primary)' }}>
                {confirmDelete.label}
              </strong>
              {' '}
              will be permanently removed from the workspace list.
              {confirmDelete.type === 'project' && (
                <>
                  {' '}
                  This project currently contains {projectStats[confirmDelete.id]?.sampleCount ?? 0} sample(s).
                </>
              )}
            </div>
            <div style={s.confirmActions}>
              <button
                type="button"
                style={s.confirmCancel}
                onClick={() => setConfirmDelete(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                style={s.confirmDelete}
                onClick={() => (
                  confirmDelete.type === 'project'
                    ? handleDeleteProject(confirmDelete.id)
                    : handleDeleteSample(confirmDelete.id)
                )}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
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
