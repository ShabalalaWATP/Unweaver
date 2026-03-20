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
    flexDirection: 'column',
    gap: '16px',
    animation: 'unweaver-fade-in 0.6s ease',
    position: 'relative',
  } as React.CSSProperties,
  emptyGlow: {
    position: 'absolute',
    width: '300px',
    height: '300px',
    borderRadius: '50%',
    background: 'radial-gradient(circle, rgba(88,166,255,0.06) 0%, transparent 70%)',
    pointerEvents: 'none',
  } as React.CSSProperties,
  emptyLogo: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    marginBottom: '4px',
  } as React.CSSProperties,
  emptyTerminal: {
    fontFamily: 'var(--font-mono)',
    fontSize: '28px',
    fontWeight: 700,
    background: 'linear-gradient(135deg, var(--accent) 0%, var(--purple, #bc8cff) 50%, var(--accent-bright) 100%)',
    backgroundSize: '200% 200%',
    animation: 'unweaver-gradient-flow 6s ease infinite',
    WebkitBackgroundClip: 'text',
    WebkitTextFillColor: 'transparent',
    letterSpacing: '0.06em',
  } as React.CSSProperties,
  emptyCursor: {
    display: 'inline-block',
    width: '2px',
    height: '28px',
    background: 'var(--accent)',
    animation: 'unweaver-cursor-blink 1s step-end infinite',
    marginLeft: '2px',
    borderRadius: '1px',
  } as React.CSSProperties,
  emptySubtitle: {
    fontSize: '13px',
    color: 'var(--text-muted)',
    letterSpacing: '0.02em',
  } as React.CSSProperties,
  emptyHint: {
    display: 'flex',
    gap: '24px',
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
                    <div style={styles.emptyLogo}>
                      <span style={styles.emptyTerminal}>UNWEAVER</span>
                      <span style={styles.emptyCursor} />
                    </div>
                    <div style={styles.emptySubtitle}>
                      Agentic code deobfuscation workbench
                    </div>
                    <div style={styles.emptyHint}>
                      <span style={styles.emptyHintItem}>
                        Upload a file or paste code to begin
                      </span>
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
