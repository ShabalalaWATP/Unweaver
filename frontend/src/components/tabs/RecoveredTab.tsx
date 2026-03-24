import { useCallback, useState } from 'react';
import { Copy, Check } from 'lucide-react';
import type { SampleDetail } from '@/types';
import CodeViewer from '@/components/editors/CodeViewer';
import { useToast } from '@/components/common/Toast';
import WorkspaceBundleViewer from '@/components/workspace/WorkspaceBundleViewer';

interface RecoveredTabProps {
  sample: SampleDetail;
  highlightText?: string | null;
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

const copyBar: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'flex-end',
  padding: '4px 8px',
  background: 'var(--bg-secondary)',
  borderBottom: '1px solid var(--border)',
  flexShrink: 0,
};

const copyBtnStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: '5px',
  padding: '4px 10px',
  fontSize: '11px',
  fontWeight: 500,
  borderRadius: 'var(--radius-md)',
  border: '1px solid var(--border)',
  background: 'var(--bg-tertiary)',
  color: 'var(--text-secondary)',
  cursor: 'pointer',
  transition: 'all 0.15s',
};

export default function RecoveredTab({ sample, highlightText }: RecoveredTabProps) {
  const toast = useToast();
  const [copied, setCopied] = useState(false);

  const handleCopyAll = useCallback(() => {
    if (!sample.recovered_text) return;
    navigator.clipboard.writeText(sample.recovered_text);
    setCopied(true);
    toast.success('Recovered code copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  }, [sample.recovered_text, toast]);

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

  if (sample.language === 'workspace') {
    return (
      <WorkspaceBundleViewer
        bundleText={sample.recovered_text}
        title="Recovered Workspace Bundle"
        description="You are browsing the reconstructed files from the recovered workspace bundle. File boundaries are preserved so the codebase reads like a codebase, not one merged buffer."
        accent="recovered"
        originalBundleText={sample.original_text}
        sampleId={sample.id}
      />
    );
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={copyBar}>
        <button
          style={{
            ...copyBtnStyle,
            ...(copied ? { color: 'var(--success)', borderColor: 'var(--success)' } : {}),
          }}
          onClick={handleCopyAll}
          onMouseEnter={(e) => {
            if (!copied) {
              e.currentTarget.style.borderColor = 'var(--accent)';
              e.currentTarget.style.color = 'var(--accent)';
            }
          }}
          onMouseLeave={(e) => {
            if (!copied) {
              e.currentTarget.style.borderColor = 'var(--border)';
              e.currentTarget.style.color = 'var(--text-secondary)';
            }
          }}
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
          {copied ? 'Copied!' : 'Copy All'}
        </button>
      </div>
      <CodeViewer
        value={sample.recovered_text}
        language={sample.language}
        readOnly={true}
        highlightText={highlightText}
      />
    </div>
  );
}
