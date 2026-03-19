import type { SampleDetail } from '@/types';
import CodeViewer from '@/components/editors/CodeViewer';

interface RecoveredTabProps {
  sample: SampleDetail;
}

const emptyState: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  height: '100%',
  color: 'var(--text-muted)',
  fontSize: '13px',
  flexDirection: 'column',
  gap: '6px',
};

export default function RecoveredTab({ sample }: RecoveredTabProps) {
  if (!sample.recovered_text) {
    return (
      <div style={emptyState}>
        <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-secondary)' }}>
          No recovered code yet
        </div>
        <div>Run analysis to deobfuscate this sample</div>
      </div>
    );
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <CodeViewer
        value={sample.recovered_text}
        language={sample.language}
        readOnly={true}
      />
    </div>
  );
}
