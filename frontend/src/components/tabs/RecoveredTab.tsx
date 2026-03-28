import { useCallback, useState } from 'react';
import { Copy, Check } from 'lucide-react';
import type { AnalysisState, SampleDetail } from '@/types';
import CodeViewer from '@/components/editors/CodeViewer';
import { useToast } from '@/components/common/Toast';
import WorkspaceBundleViewer from '@/components/workspace/WorkspaceBundleViewer';

interface RecoveredTabProps {
  sample: SampleDetail;
  analysisState?: AnalysisState | null;
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

const statusCard: React.CSSProperties = {
  margin: '14px 14px 0',
  padding: '14px 16px',
  borderRadius: '18px',
  border: '1px solid rgba(88,166,255,0.16)',
  background: 'linear-gradient(160deg, rgba(88,166,255,0.1), rgba(17,21,28,0.9))',
  display: 'flex',
  flexDirection: 'column',
  gap: '8px',
};

const statusEyebrow: React.CSSProperties = {
  fontSize: '10px',
  fontWeight: 700,
  textTransform: 'uppercase',
  letterSpacing: '0.12em',
  color: 'var(--accent-bright)',
};

const statusTitle: React.CSSProperties = {
  fontSize: '15px',
  fontWeight: 700,
  color: 'var(--text-primary)',
};

const statusBody: React.CSSProperties = {
  fontSize: '12px',
  lineHeight: '1.6',
  color: 'var(--text-secondary)',
};

const statusChips: React.CSSProperties = {
  display: 'flex',
  gap: '8px',
  flexWrap: 'wrap',
};

const statusChip: React.CSSProperties = {
  padding: '4px 9px',
  borderRadius: '999px',
  background: 'rgba(255,255,255,0.05)',
  border: '1px solid rgba(255,255,255,0.08)',
  color: 'var(--text-secondary)',
  fontSize: '10px',
  fontFamily: 'var(--font-mono)',
};

const statusNote: React.CSSProperties = {
  fontSize: '11px',
  lineHeight: '1.55',
  color: 'var(--text-muted)',
};

function formatPercent(value: number | null | undefined): string | null {
  return typeof value === 'number' ? `${Math.round(value * 100)}%` : null;
}

function resultTitle(resultKind: string | null | undefined, bestEffort: boolean): string {
  switch (resultKind) {
    case 'completed_recovery':
      return 'Recovered output';
    case 'partial_recovery':
      return 'Partial recovery';
    case 'stopped_best_effort':
      return 'Stopped best-effort state';
    case 'failed_best_effort':
      return 'Failure best-effort state';
    default:
      return bestEffort ? 'Best-effort recovered output' : 'Recovered output';
  }
}

export default function RecoveredTab({ sample, analysisState, highlightText }: RecoveredTabProps) {
  const toast = useToast();
  const [copied, setCopied] = useState(false);
  const savedAnalysis = sample.saved_analysis;
  const iterationState = analysisState?.iteration_state;
  const workspaceContext = analysisState?.workspace_context ?? savedAnalysis?.workspace_context ?? null;
  const displayConfidence = iterationState?.coverage_adjusted_confidence
    ?? savedAnalysis?.coverage_adjusted_confidence
    ?? analysisState?.confidence?.overall
    ?? savedAnalysis?.confidence_score
    ?? null;
  const rawConfidence = iterationState?.raw_confidence
    ?? analysisState?.confidence?.overall
    ?? savedAnalysis?.raw_confidence_score
    ?? savedAnalysis?.confidence_score
    ?? null;
  const confidenceScopeNote = iterationState?.confidence_scope_note
    ?? savedAnalysis?.confidence_scope_note
    ?? workspaceContext?.coverage_scope_note
    ?? null;
  const stopReason = iterationState?.stop_reason ?? savedAnalysis?.stop_reason ?? null;
  const fatalError = iterationState?.fatal_error ?? savedAnalysis?.fatal_error ?? null;
  const resultKind = iterationState?.result_kind ?? savedAnalysis?.result_kind ?? null;
  const bestEffort = iterationState?.best_effort
    ?? savedAnalysis?.best_effort
    ?? (resultKind ? resultKind !== 'completed_recovery' : false);
  const statusHeading = resultTitle(resultKind, Boolean(bestEffort));
  const supportedFileCount = workspaceContext?.supported_file_count ?? null;
  const targetedFileCount = workspaceContext?.targeted_file_count ?? workspaceContext?.targeted_files?.length ?? null;
  const remainingSupportedCount = workspaceContext?.remaining_supported_file_count ?? null;
  const remainingFrontier = workspaceContext?.remaining_frontier_paths ?? [];
  const remainingSupportedPreview = workspaceContext?.remaining_supported_paths_preview ?? [];
  const unsupportedLanguages = workspaceContext?.unsupported_languages ?? [];
  const bannerNeeded = Boolean(
    resultKind
    || stopReason
    || fatalError
    || confidenceScopeNote
    || displayConfidence !== null
    || sample.language === 'workspace',
  );

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

  const statusBanner = bannerNeeded ? (
    <div style={statusCard}>
      <div style={statusEyebrow}>Recovered Output Status</div>
      <div style={statusTitle}>{statusHeading}</div>
      <div style={statusBody}>
        {bestEffort
          ? 'This view shows the best available final state from the run, not a guarantee that every semantic detail or workspace file was fully recovered.'
          : 'This view shows the recovered output produced by the completed deobfuscation pass.'}
      </div>
      <div style={statusChips}>
        {displayConfidence !== null && (
          <span style={statusChip}>display conf {formatPercent(displayConfidence)}</span>
        )}
        {rawConfidence !== null && rawConfidence !== displayConfidence && (
          <span style={statusChip}>raw conf {formatPercent(rawConfidence)}</span>
        )}
        {sample.language === 'workspace' && targetedFileCount !== null && supportedFileCount !== null && (
          <span style={statusChip}>targeted {targetedFileCount}/{supportedFileCount}</span>
        )}
        {sample.language === 'workspace' && remainingSupportedCount !== null && (
          <span style={statusChip}>remaining supported {remainingSupportedCount}</span>
        )}
        {sample.language === 'workspace' && typeof workspaceContext?.workspace_pass_index === 'number' && (
          <span style={statusChip}>
            batches {workspaceContext.workspace_pass_index}
            {typeof workspaceContext?.workspace_pass_count_estimate === 'number'
              && workspaceContext.workspace_pass_count_estimate > 0
              ? `/${workspaceContext.workspace_pass_count_estimate}`
              : ''}
          </span>
        )}
        {sample.language === 'workspace' && remainingFrontier.length > 0 && (
          <span style={statusChip}>remaining hotspots {remainingFrontier.length}</span>
        )}
      </div>
      {stopReason && (
        <div style={statusNote}>Stop reason: {stopReason}</div>
      )}
      {sample.language === 'workspace' && remainingFrontier.length > 0 && (
        <div style={statusNote}>
          Deferred hotspot paths: {remainingFrontier.slice(0, 4).join(', ')}
          {remainingFrontier.length > 4 ? ' ...' : ''}
        </div>
      )}
      {sample.language === 'workspace' && remainingSupportedPreview.length > 0 && (
        <div style={statusNote}>
          Deferred supported paths: {remainingSupportedPreview.slice(0, 4).join(', ')}
          {remainingSupportedPreview.length > 4 ? ' ...' : ''}
        </div>
      )}
      {sample.language === 'workspace' && unsupportedLanguages.length > 0 && (
        <div style={statusNote}>
          Unsupported languages seen in the scan: {unsupportedLanguages.slice(0, 4).join(', ')}
          {unsupportedLanguages.length > 4 ? ' ...' : ''}
        </div>
      )}
      {confidenceScopeNote && (
        <div style={statusNote}>{confidenceScopeNote}</div>
      )}
      {fatalError && (
        <div style={{ ...statusNote, color: 'var(--danger)' }}>{fatalError}</div>
      )}
    </div>
  ) : null;

  if (sample.language === 'workspace') {
    return (
      <div style={{ height: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        {statusBanner}
        <div style={{ flex: 1, minHeight: 0, paddingTop: statusBanner ? '14px' : 0 }}>
          <WorkspaceBundleViewer
            bundleText={sample.recovered_text}
            title="Recovered Workspace Bundle"
            description="You are browsing the reconstructed files from the recovered workspace bundle. File boundaries are preserved so the codebase reads like a codebase, not one merged buffer."
            accent="recovered"
            originalBundleText={sample.original_text}
            sampleId={sample.id}
          />
        </div>
      </div>
    );
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {statusBanner}
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
