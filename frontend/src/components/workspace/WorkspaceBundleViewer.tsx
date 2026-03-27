import { useEffect, useState } from 'react';
import { Files, FolderTree, AlertTriangle, Braces, Download } from 'lucide-react';

import CodeViewer from '@/components/editors/CodeViewer';
import { formatFileSize, truncate } from '@/utils/format';
import { parseWorkspaceBundle } from '@/utils/workspaceBundle';

interface WorkspaceBundleViewerProps {
  bundleText: string;
  title: string;
  description: string;
  accent?: 'original' | 'recovered';
  /** Original bundle text for comparison — enables per-file change summaries. */
  originalBundleText?: string;
  /** Sample ID — needed for file export. */
  sampleId?: string;
}

const s = {
  root: {
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    background: 'var(--bg-primary)',
  } as React.CSSProperties,
  intro: {
    padding: '16px 18px',
    borderBottom: '1px solid var(--border)',
    background: 'linear-gradient(180deg, rgba(88,166,255,0.08), rgba(88,166,255,0.02))',
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
  } as React.CSSProperties,
  introHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    color: 'var(--text-primary)',
  } as React.CSSProperties,
  introTitle: {
    fontSize: '15px',
    fontWeight: 700,
  } as React.CSSProperties,
  introBody: {
    fontSize: '12px',
    lineHeight: '1.6',
    color: 'var(--text-secondary)',
    maxWidth: '78ch',
  } as React.CSSProperties,
  statStrip: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
  } as React.CSSProperties,
  statChip: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    padding: '4px 9px',
    borderRadius: '999px',
    background: 'rgba(255,255,255,0.05)',
    border: '1px solid rgba(255,255,255,0.08)',
    color: 'var(--text-secondary)',
    fontSize: '10px',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  body: {
    flex: 1,
    minHeight: 0,
    display: 'grid',
    gridTemplateColumns: '280px minmax(0, 1fr)',
  } as React.CSSProperties,
  sidebar: {
    borderRight: '1px solid var(--border)',
    background: 'var(--bg-secondary)',
    display: 'flex',
    flexDirection: 'column',
    minHeight: 0,
  } as React.CSSProperties,
  sidebarTitle: {
    padding: '12px 14px 10px',
    fontSize: '10px',
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.12em',
    color: 'var(--text-muted)',
    borderBottom: '1px solid var(--border)',
  } as React.CSSProperties,
  fileList: {
    flex: 1,
    overflowY: 'auto',
    padding: '8px',
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
  } as React.CSSProperties,
  fileRow: {
    padding: '10px 10px 9px',
    borderRadius: '14px',
    border: '1px solid var(--border-subtle)',
    background: 'transparent',
    cursor: 'pointer',
    transition: 'all 0.15s ease',
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
    textAlign: 'left',
    appearance: 'none',
  } as React.CSSProperties,
  fileRowActive: {
    background: 'rgba(88,166,255,0.08)',
    borderColor: 'rgba(88,166,255,0.22)',
  } as React.CSSProperties,
  filePath: {
    fontSize: '11px',
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-mono)',
    lineHeight: 1.45,
    wordBreak: 'break-word',
  } as React.CSSProperties,
  fileMeta: {
    display: 'flex',
    gap: '6px',
    flexWrap: 'wrap',
    alignItems: 'center',
  } as React.CSSProperties,
  fileTag: {
    padding: '2px 7px',
    borderRadius: '999px',
    background: 'var(--bg-tertiary)',
    border: '1px solid var(--border-subtle)',
    fontSize: '10px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
  content: {
    minWidth: 0,
    display: 'flex',
    flexDirection: 'column',
    minHeight: 0,
  } as React.CSSProperties,
  contentHeader: {
    padding: '12px 16px 10px',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    background: 'rgba(17,21,28,0.65)',
  } as React.CSSProperties,
  contentTitle: {
    fontSize: '13px',
    fontWeight: 700,
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-mono)',
    wordBreak: 'break-word',
  } as React.CSSProperties,
  contentMeta: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
  } as React.CSSProperties,
  note: {
    fontSize: '11px',
    color: 'var(--text-muted)',
    lineHeight: '1.5',
  } as React.CSSProperties,
};

function getPriorityTone(tag: string): React.CSSProperties {
  if (tag === 'suspicious') {
    return {
      background: 'rgba(248,81,73,0.1)',
      border: '1px solid rgba(248,81,73,0.2)',
      color: 'var(--danger)',
    };
  }
  if (tag === 'entrypoint') {
    return {
      background: 'rgba(63,185,80,0.1)',
      border: '1px solid rgba(63,185,80,0.2)',
      color: 'var(--success)',
    };
  }
  if (tag === 'manifest') {
    return {
      background: 'rgba(210,153,34,0.12)',
      border: '1px solid rgba(210,153,34,0.24)',
      color: 'var(--warning)',
    };
  }
  return {};
}

function generateFileSummary(
  originalText: string | undefined,
  recoveredText: string,
  _language: string,
): string | null {
  if (!originalText) return null;
  if (originalText === recoveredText) {
    return 'No textual changes detected between the bundled original and recovered file.';
  }

  const origLines = originalText.split('\n').length;
  const recLines = recoveredText.split('\n').length;
  const origLen = originalText.length;
  const recLen = recoveredText.length;

  const parts: string[] = [];

  // Size change
  const sizeRatio = recLen / Math.max(origLen, 1);
  if (sizeRatio < 0.5) parts.push(`Significantly reduced (${Math.round((1 - sizeRatio) * 100)}% smaller)`);
  else if (sizeRatio > 1.5) parts.push(`Expanded (${Math.round((sizeRatio - 1) * 100)}% larger — decoded payloads inlined)`);
  else if (Math.abs(origLen - recLen) > 100) parts.push(`Size adjusted (${origLines}→${recLines} lines)`);

  // Detect common transform patterns
  const origHasB64 = /[A-Za-z0-9+/=]{40,}/.test(originalText);
  const recHasB64 = /[A-Za-z0-9+/=]{40,}/.test(recoveredText);
  if (origHasB64 && !recHasB64) parts.push('Base64 payloads decoded');

  const origHasHex = /(?:\\x[0-9a-f]{2}){4,}/i.test(originalText);
  const recHasHex = /(?:\\x[0-9a-f]{2}){4,}/i.test(recoveredText);
  if (origHasHex && !recHasHex) parts.push('Hex-encoded strings decoded');

  const origHasEval = /\beval\s*\(|\bexec\s*\(|\bInvoke-Expression\b/i.test(originalText);
  const recHasEval = /\beval\s*\(|\bexec\s*\(|\bInvoke-Expression\b/i.test(recoveredText);
  if (origHasEval && !recHasEval) parts.push('eval/exec calls resolved');

  // Identifier quality
  const origShortIds = (originalText.match(/\b[a-zA-Z_]\b|\b[a-zA-Z_][a-zA-Z0-9]\b/g) || []).length;
  const recShortIds = (recoveredText.match(/\b[a-zA-Z_]\b|\b[a-zA-Z_][a-zA-Z0-9]\b/g) || []).length;
  if (origShortIds > 10 && recShortIds < origShortIds * 0.5) parts.push('Obfuscated identifiers renamed');

  if (parts.length === 0 && originalText !== recoveredText) {
    parts.push('Minor structural cleanup detected');
  }

  return parts.join('. ') + '.';
}

export default function WorkspaceBundleViewer({
  bundleText,
  title,
  description,
  accent = 'original',
  originalBundleText,
  sampleId,
}: WorkspaceBundleViewerProps) {
  const [bundle, setBundle] = useState(() => parseWorkspaceBundle(bundleText));
  const [selectedPath, setSelectedPath] = useState<string | null>(bundle?.files[0]?.path ?? null);
  const [originalBundle, setOriginalBundle] = useState(() =>
    accent === 'recovered' && originalBundleText ? parseWorkspaceBundle(originalBundleText) : null,
  );

  useEffect(() => {
    const nextBundle = parseWorkspaceBundle(bundleText);
    setBundle(nextBundle);
    setSelectedPath((currentPath) => {
      if (!nextBundle?.files.length) return null;
      if (currentPath && nextBundle.files.some((file) => file.path === currentPath)) {
        return currentPath;
      }
      return nextBundle.files[0].path;
    });
  }, [bundleText]);

  useEffect(() => {
    setOriginalBundle(
      accent === 'recovered' && originalBundleText
        ? parseWorkspaceBundle(originalBundleText)
        : null,
    );
  }, [accent, originalBundleText]);

  const activeFile = bundle?.files.find((file) => file.path === selectedPath) ?? bundle?.files[0] ?? null;

  const originalFileMap = originalBundle
    ? Object.fromEntries(originalBundle.files.map((f) => [f.path, f.text]))
    : null;

  if (!bundle || !activeFile) {
    return (
      <div style={{ height: '100%' }}>
        <CodeViewer value={bundleText} language="plaintext" readOnly={true} />
      </div>
    );
  }

  const introTone = accent === 'recovered'
    ? 'linear-gradient(180deg, rgba(63,185,80,0.10), rgba(63,185,80,0.02))'
    : 'linear-gradient(180deg, rgba(88,166,255,0.08), rgba(88,166,255,0.02))';

  return (
    <div style={s.root}>
      <div style={{ ...s.intro, background: introTone }}>
        <div style={s.introHeader}>
          <FolderTree size={16} color="var(--accent)" />
          <div style={s.introTitle}>{title}</div>
        </div>
        <div style={s.introBody}>{description}</div>
        <div style={s.statStrip}>
          <span style={s.statChip}>
            <Files size={12} />
            {bundle.included_files} bundled files
          </span>
          <span style={s.statChip}>
            <Braces size={12} />
            {bundle.archive_name}
          </span>
          {bundle.omitted_files > 0 && (
            <span style={s.statChip}>{bundle.omitted_files} omitted</span>
          )}
          {!!bundle.entry_points.length && (
            <span style={s.statChip}>{bundle.entry_points.length} entrypoints</span>
          )}
          {!!bundle.suspicious_files.length && (
            <span style={s.statChip}>
              <AlertTriangle size={12} />
              {bundle.suspicious_files.length} suspicious
            </span>
          )}
        </div>
      </div>

      <div style={s.body}>
        <div style={s.sidebar}>
          <div style={s.sidebarTitle}>Bundled Files</div>
          <div style={s.fileList}>
            {bundle.files.map((file) => {
              const isActive = file.path === activeFile.path;
              return (
                <button
                  key={file.path}
                  type="button"
                  style={{
                    ...s.fileRow,
                    ...(isActive ? s.fileRowActive : {}),
                  }}
                  onClick={() => setSelectedPath(file.path)}
                >
                  <div style={s.filePath}>{truncate(file.path, 90)}</div>
                  <div style={s.fileMeta}>
                    <span style={s.fileTag}>{file.language}</span>
                    <span style={s.fileTag}>{formatFileSize(file.size_bytes)}</span>
                    {file.priority.map((tag) => (
                      <span
                        key={`${file.path}-${tag}`}
                        style={{
                          ...s.fileTag,
                          ...getPriorityTone(tag),
                        }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        <div style={s.content}>
          <div style={s.contentHeader}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ ...s.contentTitle, flex: 1 }}>{activeFile.path}</div>
              {sampleId && (
                <button
                  type="button"
                  onClick={() => {
                    import('@/services/api').then((api) => {
                      api.exportSingleFile(sampleId!, activeFile.path, accent === 'recovered' ? 'recovered' : 'original')
                        .then(({ blob, filename }) => {
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = filename ?? activeFile.path.split('/').pop() ?? 'file.txt';
                          a.click();
                          URL.revokeObjectURL(url);
                        });
                    });
                  }}
                  style={{
                    padding: '4px 10px',
                    fontSize: '10px',
                    fontWeight: 500,
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--border)',
                    background: 'var(--bg-tertiary)',
                    color: 'var(--text-secondary)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    flexShrink: 0,
                    appearance: 'none',
                  }}
                  title="Download this file"
                >
                  <Download size={10} />
                  Download File
                </button>
              )}
            </div>
            <div style={s.contentMeta}>
              <span style={s.fileTag}>{activeFile.language}</span>
              <span style={s.fileTag}>{formatFileSize(activeFile.size_bytes)}</span>
              {activeFile.priority.map((tag) => (
                <span
                  key={`${activeFile.path}-active-${tag}`}
                  style={{
                    ...s.fileTag,
                    ...getPriorityTone(tag),
                  }}
                >
                  {tag}
                </span>
              ))}
            </div>
            <div style={s.note}>
              {bundle.bundle_note || 'This workspace upload is stored as a bounded bundle of prioritized files, not as one flat source file.'}
            </div>
          </div>
          {/* Per-file recovery summary (recovered mode only) */}
          {accent === 'recovered' && originalFileMap && (() => {
            const summary = generateFileSummary(
              originalFileMap[activeFile.path],
              activeFile.text,
              activeFile.language,
            );
            if (!summary) return null;
            const isUnchanged = originalFileMap[activeFile.path] === activeFile.text;
            return (
              <div style={{
                padding: '10px 16px',
                borderBottom: '1px solid var(--border)',
                background: isUnchanged
                  ? 'rgba(63,185,80,0.06)'
                  : 'linear-gradient(90deg, rgba(88,166,255,0.08), rgba(88,166,255,0.02))',
                fontSize: '12px',
                lineHeight: '1.6',
                color: 'var(--text-secondary)',
                display: 'flex',
                gap: '8px',
                alignItems: 'flex-start',
              }}>
                <span style={{
                  fontSize: '10px',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  color: isUnchanged ? 'var(--success)' : 'var(--accent)',
                  flexShrink: 0,
                  marginTop: '1px',
                }}>
                  HEURISTIC
                </span>
                <span>
                  Heuristic diff summary: {summary}
                </span>
              </div>
            );
          })()}
          <div style={{ flex: 1, minHeight: 0 }}>
            <CodeViewer
              value={activeFile.text}
              language={activeFile.language}
              readOnly={true}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
