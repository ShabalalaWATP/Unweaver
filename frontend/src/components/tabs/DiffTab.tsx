import type { SampleDetail } from '@/types';
import DiffViewer from '@/components/editors/DiffViewer';

interface DiffTabProps {
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

export default function DiffTab({ sample }: DiffTabProps) {
  if (!sample.recovered_text) {
    return (
      <div style={emptyState}>
        <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-secondary)' }}>
          No diff available
        </div>
        <div>Run analysis to generate a comparison</div>
      </div>
    );
  }

  return (
    <div style={{ height: '100%' }}>
      <DiffViewer
        original={sample.original_text}
        recovered={sample.recovered_text}
      />
    </div>
  );
}
