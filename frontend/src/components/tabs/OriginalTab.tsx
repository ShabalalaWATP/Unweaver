import type { SampleDetail } from '@/types';
import CodeViewer from '@/components/editors/CodeViewer';

interface OriginalTabProps {
  sample: SampleDetail;
}

export default function OriginalTab({ sample }: OriginalTabProps) {
  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <CodeViewer
        value={sample.original_text}
        language={sample.language}
        readOnly={true}
      />
    </div>
  );
}
