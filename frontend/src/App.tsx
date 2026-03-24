import { useState, useCallback, useEffect, useRef } from 'react';
import type { AnalysisState } from '@/types';
import { useSample, useAnalysisStatus, loadPersistedState, savePersistedState } from '@/hooks/useApi';
import { useToast } from '@/components/common/Toast';
import * as api from '@/services/api';
import Sidebar from '@/components/layout/Sidebar';
import TopBar from '@/components/layout/TopBar';
import RightPanel from '@/components/layout/RightPanel';
import WorkspaceTabs from '@/components/layout/WorkspaceTabs';
import ProviderSettingsScreen from '@/components/settings/ProviderSettings';
import traceAtlasGraphic from '@/assets/graphics/trace-atlas.svg';

type View = 'workspace' | 'settings';

const styles = {
  container: {
    display: 'flex',
    height: '100vh',
    overflow: 'hidden',
    background: 'var(--bg-primary)',
  } as React.CSSProperties,
  main: {
    display: 'flex',
    flexDirection: 'column',
    flex: 1,
    minWidth: 0,
    overflow: 'hidden',
  } as React.CSSProperties,
  workspace: {
    display: 'flex',
    flex: 1,
    overflow: 'hidden',
    position: 'relative',
  } as React.CSSProperties,
  meshOverlay: {
    position: 'absolute',
    inset: 0,
    pointerEvents: 'none',
    zIndex: 0,
  } as React.CSSProperties,
  content: {
    flex: 1,
    minWidth: 0,
    overflow: 'hidden',
    display: 'flex',
    flexDirection: 'column',
  } as React.CSSProperties,
  emptyState: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flex: 1,
    animation: 'unweaver-fade-in 0.6s ease',
    position: 'relative',
    padding: '40px',
    overflow: 'hidden',
  } as React.CSSProperties,
  emptyGlow: {
    position: 'absolute',
    width: '520px',
    height: '520px',
    borderRadius: '50%',
    background: 'radial-gradient(circle, rgba(88,166,255,0.1) 0%, transparent 72%)',
    pointerEvents: 'none',
    top: '-160px',
    right: '-110px',
  } as React.CSSProperties,
  emptyLayout: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '42px',
    width: '100%',
    maxWidth: '1180px',
    flexWrap: 'wrap-reverse',
    position: 'relative',
    zIndex: 1,
  } as React.CSSProperties,
  emptyCopy: {
    flex: '1 1 320px',
    minWidth: '280px',
    maxWidth: '420px',
    display: 'flex',
    flexDirection: 'column',
    gap: '14px',
  } as React.CSSProperties,
  emptyEyebrow: {
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.18em',
    color: 'var(--accent-bright)',
    fontWeight: 700,
  } as React.CSSProperties,
  emptyLogo: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  } as React.CSSProperties,
  emptyTerminal: {
    fontFamily: 'var(--font-ui)',
    fontSize: '56px',
    fontWeight: 700,
    lineHeight: 0.95,
    background: 'linear-gradient(135deg, var(--accent-bright) 0%, var(--accent) 48%, #5eead4 100%)',
    backgroundSize: '200% 200%',
    animation: 'unweaver-gradient-flow 6s ease infinite',
    WebkitBackgroundClip: 'text',
    WebkitTextFillColor: 'transparent',
    letterSpacing: '-0.04em',
  } as React.CSSProperties,
  emptyCursor: {
    display: 'inline-block',
    width: '2px',
    height: '52px',
    background: 'var(--accent)',
    animation: 'unweaver-cursor-blink 1s step-end infinite',
    marginLeft: '2px',
    borderRadius: '1px',
  } as React.CSSProperties,
  emptyLead: {
    fontSize: '16px',
    lineHeight: 1.45,
    color: 'var(--text-secondary)',
    maxWidth: '34ch',
  } as React.CSSProperties,
  emptySubtitle: {
    fontSize: '13px',
    color: 'var(--text-muted)',
    letterSpacing: '0.02em',
  } as React.CSSProperties,
  emptyHint: {
    display: 'flex',
    gap: '12px',
    flexWrap: 'wrap',
    marginTop: '12px',
  } as React.CSSProperties,
  emptyHintItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    fontSize: '11px',
    color: 'var(--text-muted)',
    padding: '6px 14px',
    borderRadius: 'var(--radius-lg)',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
  } as React.CSSProperties,
  emptyArtWrap: {
    flex: '1 1 500px',
    minWidth: '320px',
    display: 'flex',
    justifyContent: 'center',
    position: 'relative',
  } as React.CSSProperties,
  emptyArtFrame: {
    width: '100%',
    maxWidth: '700px',
    padding: '18px',
    borderRadius: '34px',
    background: 'linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01))',
    border: '1px solid rgba(255,255,255,0.08)',
    boxShadow: '0 30px 80px rgba(0, 0, 0, 0.35)',
  } as React.CSSProperties,
  emptyArt: {
    width: '100%',
    height: 'auto',
    display: 'block',
    filter: 'drop-shadow(0 22px 34px rgba(0, 0, 0, 0.28))',
  } as React.CSSProperties,
};

export default function App() {
  // ── Restore persisted state ────────────────────────────────────────
  const persisted = useRef(loadPersistedState());

  const [view, setView] = useState<View>(
    (persisted.current.view as View) ?? 'workspace',
  );
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(
    persisted.current.selectedProjectId,
  );
  const [selectedSampleId, setSelectedSampleId] = useState<string | null>(
    persisted.current.selectedSampleId,
  );
  const [activeTab, setActiveTab] = useState<string>(
    persisted.current.activeTab ?? 'original',
  );
  const [analysisState, setAnalysisState] = useState<AnalysisState | null>(null);

  const toast = useToast();

  // Local flag: set to true immediately when user clicks "Analyse"
  // so polling starts before the sample refetch completes.
  const [analysisActive, setAnalysisActive] = useState(false);

  const { sample, refetch: refetchSample } = useSample(selectedSampleId);

  // isRunning includes the local flag so polling starts instantly
  const isRunning =
    sample?.status === 'running' ||
    sample?.status === 'pending' ||
    analysisActive;
  const analysisStatus = useAnalysisStatus(selectedSampleId, isRunning);

  // ── Persist state changes to localStorage ──────────────────────────
  useEffect(() => {
    savePersistedState({ selectedProjectId });
  }, [selectedProjectId]);

  useEffect(() => {
    savePersistedState({ selectedSampleId });
  }, [selectedSampleId]);

  useEffect(() => {
    savePersistedState({ activeTab });
  }, [activeTab]);

  useEffect(() => {
    savePersistedState({ view });
  }, [view]);

  // ── Load analysis state for persisted sample on first mount ────────
  const initialLoadDone = useRef(false);
  useEffect(() => {
    if (initialLoadDone.current) return;
    if (selectedSampleId && sample) {
      initialLoadDone.current = true;
      api.getAnalysisState(selectedSampleId).then(setAnalysisState).catch(() => {});
    }
  }, [selectedSampleId, sample]);

  const handleSelectProject = useCallback((id: string) => {
    setSelectedProjectId(id);
    setSelectedSampleId(null);
    setAnalysisState(null);
    setAnalysisActive(false);
    setView('workspace');
  }, []);

  const handleSelectSample = useCallback(async (id: string) => {
    setSelectedSampleId(id);
    setAnalysisActive(false);
    setView('workspace');
    try {
      const state = await api.getAnalysisState(id);
      setAnalysisState(state);
    } catch {
      setAnalysisState(null);
    }
  }, []);

  const handleStartAnalysis = useCallback(async () => {
    if (!selectedSampleId) return;
    try {
      setAnalysisActive(true);
      await api.startAnalysis(selectedSampleId);
      refetchSample();
      toast.info('Analysis started');
    } catch (err) {
      console.error('Failed to start analysis:', err);
      setAnalysisActive(false);
      toast.error('Failed to start analysis');
    }
  }, [selectedSampleId, refetchSample, toast]);

  const handleStopAnalysis = useCallback(async () => {
    if (!selectedSampleId) return;
    try {
      await api.stopAnalysis(selectedSampleId);
      refetchSample();
      toast.warning('Analysis stop requested');
    } catch (err) {
      console.error('Failed to stop analysis:', err);
      toast.error('Failed to stop analysis');
    }
  }, [selectedSampleId, refetchSample, toast]);

  const handleAnalysisComplete = useCallback(async () => {
    setAnalysisActive(false);
    refetchSample();
    if (selectedSampleId) {
      try {
        const state = await api.getAnalysisState(selectedSampleId);
        setAnalysisState(state);
        toast.success('Analysis completed');
      } catch {
        // State may not be available
      }
    }
  }, [refetchSample, selectedSampleId, toast]);

  // ── Detect analysis completion via polling status transitions ──────
  const prevAnalysisStatusRef = useRef<string | null>(null);

  useEffect(() => {
    const currentStatus = analysisStatus?.status ?? null;
    const prevStatus = prevAnalysisStatusRef.current;
    prevAnalysisStatusRef.current = currentStatus;

    if (
      prevStatus &&
      (prevStatus === 'running' || prevStatus === 'pending') &&
      currentStatus &&
      currentStatus !== 'running' &&
      currentStatus !== 'pending'
    ) {
      handleAnalysisComplete();
    }
  }, [analysisStatus?.status, handleAnalysisComplete]);

  // ── Periodically refresh sample data while analysis is active ──────
  useEffect(() => {
    if (!isRunning) return;
    const timer = setInterval(() => {
      refetchSample();
    }, 5000);
    return () => clearInterval(timer);
  }, [isRunning, refetchSample]);

  // ── Global keyboard shortcuts ──────────────────────────────────────
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ctrl+Enter — start analysis
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        if (selectedSampleId && !isRunning) handleStartAnalysis();
      }
      // Ctrl+Shift+S — open settings
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'S') {
        e.preventDefault();
        setView((v) => (v === 'settings' ? 'workspace' : 'settings'));
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedSampleId, isRunning, handleStartAnalysis]);

  // ── Callbacks for sidebar delete actions ────────────────────────────
  const handleDeleteProject = useCallback((id: string) => {
    if (selectedProjectId === id) {
      setSelectedProjectId(null);
      setSelectedSampleId(null);
      setAnalysisState(null);
    }
  }, [selectedProjectId]);

  const handleDeleteSample = useCallback((id: string) => {
    if (selectedSampleId === id) {
      setSelectedSampleId(null);
      setAnalysisState(null);
    }
  }, [selectedSampleId]);

  return (
    <div style={styles.container}>
      <Sidebar
        selectedProjectId={selectedProjectId}
        selectedSampleId={selectedSampleId}
        onSelectProject={handleSelectProject}
        onSelectSample={handleSelectSample}
        onOpenSettings={() => setView('settings')}
        onDeleteProject={handleDeleteProject}
        onDeleteSample={handleDeleteSample}
      />
      <div style={styles.main}>
        {view === 'settings' ? (
          <ProviderSettingsScreen onBack={() => setView('workspace')} />
        ) : (
          <>
            <TopBar
              sample={sample ?? null}
              analysisStatus={analysisStatus}
              onStartAnalysis={handleStartAnalysis}
              onStopAnalysis={handleStopAnalysis}
              onRefresh={refetchSample}
            />
            <div style={styles.workspace}>
              <div className="unweaver-mesh-bg" style={styles.meshOverlay} />
              <div style={styles.content}>
                {sample ? (
                  <WorkspaceTabs
                    sample={sample}
                    analysisState={analysisState}
                    activeTab={activeTab}
                    onTabChange={setActiveTab}
                  />
                ) : (
                  <div style={styles.emptyState}>
                    <div style={styles.emptyGlow} />
                    <div style={styles.emptyLayout}>
                      <div style={styles.emptyCopy}>
                        <span style={styles.emptyEyebrow}>Obfuscated Code Deobfuscation</span>
                        <div style={styles.emptyLogo}>
                          <span style={styles.emptyTerminal}>UNWEAVER</span>
                          <span style={styles.emptyCursor} />
                        </div>
                        <div style={styles.emptyLead}>
                          Deobfuscate obfuscated scripts, packed loaders, and hostile workspace
                          bundles in one analysis surface built for live forensic work.
                        </div>
                        <div style={styles.emptySubtitle}>
                          Upload an obfuscated file, drop a codebase, or paste suspicious code to start deobfuscation.
                        </div>
                        <div style={styles.emptyHint}>
                          <span style={styles.emptyHintItem}>
                            Folder and multi-file ingest
                          </span>
                          <span style={styles.emptyHintItem}>
                            Live transform history and findings
                          </span>
                          <span style={styles.emptyHintItem}>
                            Local workspace export after recovery
                          </span>
                        </div>
                      </div>
                      <div style={styles.emptyArtWrap}>
                        <div className="unweaver-empty-art-frame" style={styles.emptyArtFrame}>
                          <img
                            className="unweaver-empty-art"
                            src={traceAtlasGraphic}
                            alt="Abstract deobfuscation trace atlas"
                            style={styles.emptyArt}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
              {sample && (
                <RightPanel
                  sample={sample}
                  analysisState={analysisState}
                  onRefresh={refetchSample}
                />
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
