import { useState, useMemo } from 'react';
import type { SampleDetail } from '@/types';
import DiffViewer from '@/components/editors/DiffViewer';
import { parseWorkspaceBundle } from '@/utils/workspaceBundle';
import { truncate } from '@/utils/format';

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
  const [selectedFile, setSelectedFile] = useState<string | null>(null);

  const isWorkspace = sample.language === 'workspace';
  const origBundle = useMemo(
    () => (isWorkspace ? parseWorkspaceBundle(sample.original_text) : null),
    [sample.original_text, isWorkspace],
  );
  const recBundle = useMemo(
    () => (isWorkspace && sample.recovered_text ? parseWorkspaceBundle(sample.recovered_text) : null),
    [sample.recovered_text, isWorkspace],
  );

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

  // Workspace bundle: per-file diff with file selector
  if (isWorkspace && origBundle && recBundle) {
    const allPaths = Array.from(new Set([
      ...origBundle.files.map((f) => f.path),
      ...recBundle.files.map((f) => f.path),
    ]));

    const origMap = Object.fromEntries(origBundle.files.map((f) => [f.path, f.text]));
    const recMap = Object.fromEntries(recBundle.files.map((f) => [f.path, f.text]));

    const activePath = selectedFile ?? allPaths[0] ?? null;
    const origText = activePath ? origMap[activePath] ?? '' : '';
    const recText = activePath ? recMap[activePath] ?? '' : '';
    const hasChanges = (path: string) => (origMap[path] ?? '') !== (recMap[path] ?? '');

    return (
      <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        {/* File selector bar */}
        <div style={{
          display: 'flex',
          gap: '1px',
          background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border)',
          overflowX: 'auto',
          flexShrink: 0,
          padding: '0 4px',
        }}>
          {allPaths.map((path) => {
            const isActive = path === activePath;
            const changed = hasChanges(path);
            return (
              <button
                key={path}
                type="button"
                onClick={() => setSelectedFile(path)}
                style={{
                  padding: '8px 12px',
                  fontSize: '11px',
                  fontWeight: 500,
                  fontFamily: 'var(--font-mono)',
                  color: isActive ? 'var(--accent)' : changed ? 'var(--text-primary)' : 'var(--text-muted)',
                  background: isActive ? 'rgba(88,166,255,0.06)' : 'transparent',
                  border: 'none',
                  borderBottom: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  appearance: 'none',
                }}
              >
                {truncate(path.split('/').pop() ?? path, 30)}
                {changed && (
                  <span style={{
                    width: 6,
                    height: 6,
                    borderRadius: '50%',
                    background: 'var(--warning)',
                    flexShrink: 0,
                  }} />
                )}
                {!changed && (
                  <span style={{ fontSize: '9px', color: 'var(--text-muted)' }}>clean</span>
                )}
              </button>
            );
          })}
        </div>
        {/* Per-file diff */}
        <div style={{ flex: 1, minHeight: 0 }}>
          {origText === recText ? (
            <div style={{ ...emptyState, height: '100%' }}>
              <div style={{ fontSize: '13px', color: 'var(--success)' }}>
                No changes in this file
              </div>
            </div>
          ) : (
            <DiffViewer original={origText} recovered={recText} />
          )}
        </div>
      </div>
    );
  }

  // Single file: standard diff
  return (
    <div style={{ height: '100%' }}>
      <DiffViewer
        original={sample.original_text}
        recovered={sample.recovered_text}
      />
    </div>
  );
}
