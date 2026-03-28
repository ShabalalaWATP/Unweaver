import { useState, useCallback } from 'react';
import {
  Code2, FileCheck, GitCompare, Type, Shield, History, AlertTriangle, BookOpen, FileText,
} from 'lucide-react';
import type { SampleDetail, AnalysisState } from '@/types';
import OriginalTab from '@/components/tabs/OriginalTab';
import RecoveredTab from '@/components/tabs/RecoveredTab';
import DiffTab from '@/components/tabs/DiffTab';
import StringsTab from '@/components/tabs/StringsTab';
import IOCsTab from '@/components/tabs/IOCsTab';
import TransformHistoryTab from '@/components/tabs/TransformHistoryTab';
import FindingsTab from '@/components/tabs/FindingsTab';
import AgentNotebookTab from '@/components/tabs/AgentNotebookTab';
import SummaryTab from '@/components/tabs/SummaryTab';

type TabId =
  | 'summary'
  | 'original'
  | 'recovered'
  | 'diff'
  | 'strings'
  | 'iocs'
  | 'transforms'
  | 'findings'
  | 'notebook';

const TABS: { id: TabId; label: string; icon: React.ReactNode }[] = [
  { id: 'summary', label: 'Summary', icon: <FileText size={13} /> },
  { id: 'original', label: 'Original', icon: <Code2 size={13} /> },
  { id: 'recovered', label: 'Recovered', icon: <FileCheck size={13} /> },
  { id: 'diff', label: 'Diff', icon: <GitCompare size={13} /> },
  { id: 'strings', label: 'Strings', icon: <Type size={13} /> },
  { id: 'iocs', label: 'IOCs', icon: <Shield size={13} /> },
  { id: 'transforms', label: 'Transforms', icon: <History size={13} /> },
  { id: 'findings', label: 'Findings', icon: <AlertTriangle size={13} /> },
  { id: 'notebook', label: 'Notebook', icon: <BookOpen size={13} /> },
];

interface WorkspaceTabsProps {
  sample: SampleDetail;
  analysisState: AnalysisState | null;
  activeTab?: string;
  onTabChange?: (tab: string) => void;
}

const s = {
  root: {
    display: 'flex',
    flexDirection: 'column',
    flex: 1,
    overflow: 'hidden',
  } as React.CSSProperties,
  tabBar: {
    display: 'flex',
    background: 'var(--bg-secondary)',
    borderBottom: '1px solid var(--border)',
    overflowX: 'auto',
    flexShrink: 0,
    gap: '1px',
    padding: '0 4px',
  } as React.CSSProperties,
  tab: {
    padding: '10px 14px 9px',
    fontSize: '11px',
    fontWeight: 500,
    color: 'var(--text-muted)',
    cursor: 'pointer',
    borderBottom: '2px solid transparent',
    whiteSpace: 'nowrap',
    transition: 'all 0.15s ease',
    userSelect: 'none',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    position: 'relative',
  } as React.CSSProperties,
  tabActive: {
    color: 'var(--accent)',
    borderBottomColor: 'var(--accent)',
    background: 'rgba(88,166,255,0.04)',
  } as React.CSSProperties,
  tabIcon: {
    opacity: 0.6,
    flexShrink: 0,
  } as React.CSSProperties,
  tabIconActive: {
    opacity: 1,
  } as React.CSSProperties,
  countBadge: {
    fontSize: '9px',
    fontWeight: 600,
    fontFamily: 'var(--font-mono)',
    padding: '1px 5px',
    borderRadius: '8px',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-muted)',
    lineHeight: '1.3',
    minWidth: '16px',
    textAlign: 'center',
  } as React.CSSProperties,
  countBadgeActive: {
    background: 'var(--accent-muted)',
    color: 'var(--accent)',
  } as React.CSSProperties,
  content: {
    flex: 1,
    overflow: 'hidden',
  } as React.CSSProperties,
};

export default function WorkspaceTabs({ sample, analysisState, activeTab: activeTabProp, onTabChange }: WorkspaceTabsProps) {
  const activeTab = (activeTabProp ?? 'original') as TabId;
  const [codeHighlight, setCodeHighlight] = useState<string | null>(null);

  const setActiveTab = (tab: TabId) => {
    if (tab !== 'recovered') setCodeHighlight(null);
    onTabChange?.(tab);
  };

  const handleNavigateToCode = useCallback((searchText: string) => {
    setCodeHighlight(searchText);
    setActiveTab('recovered');
  }, []);

  // Count badges for data tabs
  const counts: Partial<Record<TabId, number>> = {};
  if (analysisState) {
    if (analysisState.strings?.length) counts.strings = analysisState.strings.length;
    if (analysisState.transform_history?.length) counts.transforms = analysisState.transform_history.length;
  } else if (sample.saved_analysis) {
    if (sample.saved_analysis.string_count) counts.strings = sample.saved_analysis.string_count;
    if (sample.saved_analysis.transform_count) counts.transforms = sample.saved_analysis.transform_count;
  }

  const renderContent = () => {
    switch (activeTab) {
      case 'summary':
        return <SummaryTab sample={sample} analysisState={analysisState} />;
      case 'original':
        return <OriginalTab sample={sample} />;
      case 'recovered':
        return <RecoveredTab sample={sample} analysisState={analysisState} highlightText={codeHighlight} />;
      case 'diff':
        return <DiffTab sample={sample} />;
      case 'strings':
        return <StringsTab sampleId={sample.id} />;
      case 'iocs':
        return <IOCsTab sampleId={sample.id} />;
      case 'transforms':
        return <TransformHistoryTab sampleId={sample.id} analysisState={analysisState} />;
      case 'findings':
        return <FindingsTab sampleId={sample.id} onNavigateToCode={handleNavigateToCode} />;
      case 'notebook':
        return <AgentNotebookTab analysisState={analysisState} />;
      default:
        return null;
    }
  };

  return (
    <div style={s.root}>
      <div style={s.tabBar}>
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id;
          const count = counts[tab.id];
          return (
            <div
              key={tab.id}
              style={{
                ...s.tab,
                ...(isActive ? s.tabActive : {}),
              }}
              onClick={() => setActiveTab(tab.id)}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.color = 'var(--text-secondary)';
                  e.currentTarget.style.background = 'var(--bg-hover, rgba(255,255,255,0.02))';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.color = 'var(--text-muted)';
                  e.currentTarget.style.background = 'transparent';
                }
              }}
            >
              <span style={{ ...(s.tabIcon), ...(isActive ? s.tabIconActive : {}) }}>
                {tab.icon}
              </span>
              {tab.label}
              {count !== undefined && count > 0 && (
                <span style={{
                  ...s.countBadge,
                  ...(isActive ? s.countBadgeActive : {}),
                }}>
                  {count > 99 ? '99+' : count}
                </span>
              )}
            </div>
          );
        })}
      </div>
      <div key={activeTab} className="unweaver-tab-enter" style={s.content}>{renderContent()}</div>
    </div>
  );
}
