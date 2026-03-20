import { useState, useCallback } from 'react';
import { ChevronDown, ChevronRight, AlertTriangle, Info, AlertOctagon, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { Finding, Severity } from '@/types';
import { useAsync } from '@/hooks/useApi';
import * as api from '@/services/api';

interface FindingsTabProps {
  sampleId: string;
}

const SEVERITY_CONFIG: Record<
  Severity,
  { color: string; bg: string; icon: React.ReactNode; label: string }
> = {
  critical: {
    color: 'var(--severity-critical)',
    bg: 'var(--severity-critical-bg)',
    icon: <AlertOctagon size={12} />,
    label: 'CRITICAL',
  },
  high: {
    color: 'var(--severity-high)',
    bg: 'var(--severity-high-bg)',
    icon: <AlertTriangle size={12} />,
    label: 'HIGH',
  },
  medium: {
    color: 'var(--severity-medium)',
    bg: 'var(--severity-medium-bg)',
    icon: <ShieldAlert size={12} />,
    label: 'MEDIUM',
  },
  low: {
    color: 'var(--severity-low)',
    bg: 'var(--severity-low-bg)',
    icon: <ShieldCheck size={12} />,
    label: 'LOW',
  },
  info: {
    color: 'var(--severity-info)',
    bg: 'var(--severity-info-bg)',
    icon: <Info size={12} />,
    label: 'INFO',
  },
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const s = {
  root: {
    height: '100%',
    overflow: 'auto',
    padding: '16px',
  } as React.CSSProperties,
  card: {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg, 10px)',
    marginBottom: '10px',
    overflow: 'hidden',
    transition: 'border-color 0.15s ease, box-shadow 0.15s ease',
  } as React.CSSProperties,
  cardHeader: {
    padding: '10px 14px',
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    cursor: 'pointer',
    userSelect: 'none',
    transition: 'background 0.1s',
  } as React.CSSProperties,
  severityBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '4px',
    padding: '2px 8px',
    borderRadius: 'var(--radius-sm)',
    fontSize: '10px',
    fontWeight: 700,
    letterSpacing: '0.04em',
    flexShrink: 0,
  } as React.CSSProperties,
  title: {
    fontSize: '13px',
    fontWeight: 600,
    color: 'var(--text-primary)',
    flex: 1,
  } as React.CSSProperties,
  confidenceSmall: {
    fontSize: '10px',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-muted)',
    flexShrink: 0,
  } as React.CSSProperties,
  body: {
    padding: '10px 14px',
    borderTop: '1px solid var(--border)',
  } as React.CSSProperties,
  description: {
    fontSize: '12px',
    color: 'var(--text-secondary)',
    lineHeight: '1.6',
    marginBottom: '8px',
  } as React.CSSProperties,
  evidenceBlock: {
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    padding: '8px 10px',
    fontFamily: 'var(--font-mono)',
    fontSize: '11px',
    color: 'var(--text-secondary)',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    maxHeight: 200,
    overflow: 'auto',
  } as React.CSSProperties,
  evidenceLabel: {
    fontSize: '10px',
    fontWeight: 600,
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    marginBottom: '4px',
  } as React.CSSProperties,
  confidenceBar: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginTop: '8px',
  } as React.CSSProperties,
  barTrack: {
    flex: 1,
    height: 4,
    borderRadius: 2,
    background: 'var(--bg-tertiary)',
    overflow: 'hidden',
  } as React.CSSProperties,
  emptyState: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100%',
    color: 'var(--text-muted)',
    fontSize: '13px',
  } as React.CSSProperties,
};

function getConfidenceColor(val: number): string {
  if (val >= 0.7) return 'var(--success)';
  if (val >= 0.4) return 'var(--warning)';
  return 'var(--danger)';
}

export default function FindingsTab({ sampleId }: FindingsTabProps) {
  const { data: findings, loading } = useAsync<Finding[]>(
    () => api.getFindings(sampleId),
    [sampleId],
  );
  const [expandedSet, setExpandedSet] = useState<Set<string>>(new Set());

  const toggleExpand = useCallback((id: string) => {
    setExpandedSet((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  if (loading) {
    return <div style={s.emptyState}>Loading findings...</div>;
  }

  if (!findings || findings.length === 0) {
    return <div style={s.emptyState}>No findings yet</div>;
  }

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  return (
    <div style={s.root}>
      {sorted.map((f) => {
        const cfg = SEVERITY_CONFIG[f.severity] ?? SEVERITY_CONFIG.info;
        const expanded = expandedSet.has(f.id);

        return (
          <div key={f.id} style={{ ...s.card, borderLeftColor: cfg.color, borderLeftWidth: 3 }}>
            <div
              style={s.cardHeader}
              onClick={() => toggleExpand(f.id)}
              onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--bg-tertiary)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
            >
              {expanded ? (
                <ChevronDown size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
              ) : (
                <ChevronRight size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
              )}
              <span style={{ ...s.severityBadge, color: cfg.color, background: cfg.bg }}>
                {cfg.icon}
                {cfg.label}
              </span>
              <span style={s.title}>{f.title}</span>
              <span style={s.confidenceSmall}>
                {Math.round(f.confidence * 100)}%
              </span>
            </div>
            {expanded && (
              <div style={s.body}>
                {f.description && <div style={s.description}>{f.description}</div>}
                <div style={s.confidenceBar}>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                    Confidence
                  </span>
                  <div style={s.barTrack}>
                    <div
                      style={{
                        height: '100%',
                        width: `${f.confidence * 100}%`,
                        background: getConfidenceColor(f.confidence),
                        borderRadius: 2,
                      }}
                    />
                  </div>
                  <span
                    style={{
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)',
                      color: getConfidenceColor(f.confidence),
                    }}
                  >
                    {Math.round(f.confidence * 100)}%
                  </span>
                </div>
                {f.evidence && (
                  <div style={{ marginTop: '10px' }}>
                    <div style={s.evidenceLabel}>Evidence</div>
                    <div style={s.evidenceBlock}>{f.evidence}</div>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
