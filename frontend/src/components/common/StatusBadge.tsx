import type { SampleStatus } from '@/types';

interface StatusBadgeProps {
  status: SampleStatus;
}

const STATUS_CONFIG: Record<
  SampleStatus,
  { color: string; bg: string; border: string; label: string; pulse?: boolean }
> = {
  pending: {
    color: 'var(--text-muted)',
    bg: 'var(--bg-tertiary)',
    border: 'var(--border)',
    label: 'Pending',
  },
  running: {
    color: 'var(--accent)',
    bg: 'var(--accent-muted)',
    border: 'rgba(88,166,255,0.3)',
    label: 'Running',
    pulse: true,
  },
  completed: {
    color: 'var(--success)',
    bg: 'var(--success-muted)',
    border: 'rgba(63,185,80,0.3)',
    label: 'Completed',
  },
  failed: {
    color: 'var(--danger)',
    bg: 'var(--danger-muted)',
    border: 'rgba(248,81,73,0.3)',
    label: 'Failed',
  },
  stopped: {
    color: 'var(--warning)',
    bg: 'var(--warning-muted)',
    border: 'rgba(210,153,34,0.3)',
    label: 'Stopped',
  },
};

const baseStyle: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '5px',
  padding: '2px 10px',
  borderRadius: '10px',
  fontSize: '10px',
  fontWeight: 600,
  letterSpacing: '0.04em',
  textTransform: 'uppercase',
  border: '1px solid',
  transition: 'all 0.2s ease',
};

const dotStyle: React.CSSProperties = {
  width: 6,
  height: 6,
  borderRadius: '50%',
  flexShrink: 0,
};

export default function StatusBadge({ status }: StatusBadgeProps) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.pending;

  return (
    <span
      style={{
        ...baseStyle,
        color: cfg.color,
        background: cfg.bg,
        borderColor: cfg.border,
      }}
    >
      <span
        style={{
          ...dotStyle,
          background: cfg.color,
          boxShadow: `0 0 6px ${cfg.color}`,
          ...(cfg.pulse
            ? { animation: 'unweaver-pulse 1.5s ease-in-out infinite' }
            : {}),
        }}
      />
      {cfg.label}
    </span>
  );
}
