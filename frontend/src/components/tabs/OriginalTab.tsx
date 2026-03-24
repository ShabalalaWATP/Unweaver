import type { SampleDetail } from '@/types';
import CodeViewer from '@/components/editors/CodeViewer';
import WorkspaceBundleViewer from '@/components/workspace/WorkspaceBundleViewer';

interface OriginalTabProps {
  sample: SampleDetail;
}

export default function OriginalTab({ sample }: OriginalTabProps) {
  if (sample.language === 'workspace') {
    return (
      <WorkspaceBundleViewer
        bundleText={sample.original_text}
        title="Original Workspace Bundle"
        description="This codebase upload was packaged into a workspace bundle. Browse the prioritized files extracted from the archive instead of one opaque text blob."
        sampleId={sample.id}
      />
    );
  }

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
