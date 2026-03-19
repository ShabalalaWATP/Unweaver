import { useState } from 'react';
import type { SampleDetail, AnalysisState } from '@/types';
import OriginalTab from '@/components/tabs/OriginalTab';
import RecoveredTab from '@/components/tabs/RecoveredTab';
import DiffTab from '@/components/tabs/DiffTab';
import StringsTab from '@/components/tabs/StringsTab';
import IOCsTab from '@/components/tabs/IOCsTab';
import TransformHistoryTab from '@/components/tabs/TransformHistoryTab';
import FindingsTab from '@/components/tabs/FindingsTab';
import AgentNotebookTab from '@/components/tabs/AgentNotebookTab';

type TabId =
  | 'original'
  | 'recovered'
  | 'diff'
  | 'strings'
  | 'iocs'
  | 'transforms'
  | 'findings'
  | 'notebook';

const TABS: { id: TabId; label: string }[] = [
  { id: 'original', label: 'Original' },
  { id: 'recovered', label: 'Recovered' },
  { id: 'diff', label: 'Diff' },
  { id: 'strings', label: 'Strings' },
  { id: 'iocs', label: 'IOCs' },
  { id: 'transforms', label: 'Transform History' },
  { id: 'findings', label: 'Findings' },
  { id: 'notebook', label: 'Agent Notebook' },
];

interface WorkspaceTabsProps {
  sample: SampleDetail;
  analysisState: AnalysisState | null;
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
  } as React.CSSProperties,
  tab: {
    padding: '8px 16px',
    fontSize: '11px',
    fontWeight: 500,
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    borderBottom: '2px solid transparent',
    whiteSpace: 'nowrap',
    transition: 'color 0.1s, border-color 0.1s',
    userSelect: 'none',
  } as React.CSSProperties,
  tabActive: {
    color: 'var(--text-primary)',
    borderBottomColor: 'var(--accent)',
  } as React.CSSProperties,
  content: {
    flex: 1,
    overflow: 'hidden',
  } as React.CSSProperties,
};

export default function WorkspaceTabs({ sample, analysisState }: WorkspaceTabsProps) {
  const [activeTab, setActiveTab] = useState<TabId>('original');

  const renderContent = () => {
    switch (activeTab) {
      case 'original':
        return <OriginalTab sample={sample} />;
      case 'recovered':
        return <RecoveredTab sample={sample} />;
      case 'diff':
        return <DiffTab sample={sample} />;
      case 'strings':
        return <StringsTab sampleId={sample.id} />;
      case 'iocs':
        return <IOCsTab sampleId={sample.id} />;
      case 'transforms':
        return <TransformHistoryTab sampleId={sample.id} analysisState={analysisState} />;
      case 'findings':
        return <FindingsTab sampleId={sample.id} />;
      case 'notebook':
        return <AgentNotebookTab analysisState={analysisState} />;
      default:
        return null;
    }
  };

  return (
    <div style={s.root}>
      <div style={s.tabBar}>
        {TABS.map((tab) => (
          <div
            key={tab.id}
            style={{
              ...s.tab,
              ...(activeTab === tab.id ? s.tabActive : {}),
            }}
            onClick={() => setActiveTab(tab.id)}
            onMouseEnter={(e) => {
              if (activeTab !== tab.id) {
                e.currentTarget.style.color = 'var(--text-primary)';
              }
            }}
            onMouseLeave={(e) => {
              if (activeTab !== tab.id) {
                e.currentTarget.style.color = 'var(--text-secondary)';
              }
            }}
          >
            {tab.label}
          </div>
        ))}
      </div>
      <div style={s.content}>{renderContent()}</div>
    </div>
  );
}
