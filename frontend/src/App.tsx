import { useState, useCallback, useEffect, useRef } from 'react';
import type { AnalysisState } from '@/types';
import { useSample, useAnalysisStatus } from '@/hooks/useApi';
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
    color: 'var(--text-muted)',
    fontSize: '14px',
    flexDirection: 'column',
    gap: '8px',
  } as React.CSSProperties,
  emptyTitle: {
    fontSize: '18px',
    fontWeight: 600,
    color: 'var(--text-secondary)',
    letterSpacing: '0.04em',
  } as React.CSSProperties,
};

export default function App() {
  const [view, setView] = useState<View>('workspace');
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [selectedSampleId, setSelectedSampleId] = useState<string | null>(null);
  const [analysisState, setAnalysisState] = useState<AnalysisState | null>(null);

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
    } catch (err) {
      console.error('Failed to start analysis:', err);
      setAnalysisActive(false);
    }
  }, [selectedSampleId, refetchSample]);

  const handleStopAnalysis = useCallback(async () => {
    if (!selectedSampleId) return;
    try {
      await api.stopAnalysis(selectedSampleId);
      refetchSample();
    } catch (err) {
      console.error('Failed to stop analysis:', err);
    }
  }, [selectedSampleId, refetchSample]);

  const handleAnalysisComplete = useCallback(async () => {
    setAnalysisActive(false);
    refetchSample();
    if (selectedSampleId) {
      try {
        const state = await api.getAnalysisState(selectedSampleId);
        setAnalysisState(state);
      } catch {
        // State may not be available
      }
    }
  }, [refetchSample, selectedSampleId]);

  // ── Detect analysis completion via polling status transitions ──────
  // Track the previous polling status so we fire exactly once on transition.
  const prevAnalysisStatusRef = useRef<string | null>(null);

  useEffect(() => {
    const currentStatus = analysisStatus?.status ?? null;
    const prevStatus = prevAnalysisStatusRef.current;
    prevAnalysisStatusRef.current = currentStatus;

    // Detect transition from active (running/pending) to terminal state
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
  // This keeps the sample status badge and TopBar in sync with reality.
  useEffect(() => {
    if (!isRunning) return;
    const timer = setInterval(() => {
      refetchSample();
    }, 5000);
    return () => clearInterval(timer);
  }, [isRunning, refetchSample]);

  return (
    <div style={styles.container}>
      <Sidebar
        selectedProjectId={selectedProjectId}
        selectedSampleId={selectedSampleId}
        onSelectProject={handleSelectProject}
        onSelectSample={handleSelectSample}
        onOpenSettings={() => setView('settings')}
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
                  />
                ) : (
                  <div style={styles.emptyState}>
                    <div style={styles.emptyTitle}>UNWEAVER</div>
                    <div>Select or upload a sample to begin analysis</div>
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
