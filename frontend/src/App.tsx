import { useState, useCallback } from 'react';
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

  const { sample, refetch: refetchSample } = useSample(selectedSampleId);

  const isRunning = sample?.status === 'running' || sample?.status === 'pending';
  const analysisStatus = useAnalysisStatus(selectedSampleId, isRunning);

  const handleSelectProject = useCallback((id: string) => {
    setSelectedProjectId(id);
    setSelectedSampleId(null);
    setAnalysisState(null);
    setView('workspace');
  }, []);

  const handleSelectSample = useCallback(async (id: string) => {
    setSelectedSampleId(id);
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
    await api.startAnalysis(selectedSampleId);
    refetchSample();
  }, [selectedSampleId, refetchSample]);

  const handleStopAnalysis = useCallback(async () => {
    if (!selectedSampleId) return;
    await api.stopAnalysis(selectedSampleId);
    refetchSample();
  }, [selectedSampleId, refetchSample]);

  const handleAnalysisComplete = useCallback(async () => {
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

  // When polling detects completion, update state
  if (
    analysisStatus &&
    (analysisStatus.status === 'completed' || analysisStatus.status === 'failed' || analysisStatus.status === 'stopped') &&
    sample &&
    sample.status === 'running'
  ) {
    handleAnalysisComplete();
  }

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
