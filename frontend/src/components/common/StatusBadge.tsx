import type { SampleStatus } from '@/types';

interface StatusBadgeProps {
  status: SampleStatus;
}

const STATUS_CONFIG: Record<
  SampleStatus,
  { color: string; bg: string; label: string; pulse?: boolean }
> = {
  pending: {
    color: 'var(--text-muted)',
    bg: 'var(--bg-tertiary)',
    label: 'Pending',
  },
  running: {
    color: 'var(--accent)',
    bg: 'var(--accent-muted)',
    label: 'Running',
    pulse: true,
  },
  completed: {
    color: 'var(--success)',
    bg: 'var(--success-muted)',
    label: 'Completed',
  },
  failed: {
    color: 'var(--danger)',
    bg: 'var(--danger-muted)',
    label: 'Failed',
  },
  stopped: {
    color: 'var(--warning)',
    bg: 'var(--warning-muted)',
    label: 'Stopped',
  },
};

const baseStyle: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '5px',
  padding: '2px 8px',
  borderRadius: '10px',
  fontSize: '10px',
  fontWeight: 600,
  letterSpacing: '0.03em',
  textTransform: 'uppercase',
};

const dotStyle: React.CSSProperties = {
  width: 6,
  height: 6,
  borderRadius: '50%',
  flexShrink: 0,
};

const pulseKeyframes = `
@keyframes unweaver-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
`;

// Inject keyframes once
let injected = false;
function ensureKeyframes() {
  if (injected) return;
  const sheet = document.createElement('style');
  sheet.textContent = pulseKeyframes;
  document.head.appendChild(sheet);
  injected = true;
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.pending;

  if (cfg.pulse) {
    ensureKeyframes();
  }

  return (
    <span
      style={{
        ...baseStyle,
        color: cfg.color,
        background: cfg.bg,
      }}
    >
      <span
        style={{
          ...dotStyle,
          background: cfg.color,
          ...(cfg.pulse
            ? { animation: 'unweaver-pulse 1.5s ease-in-out infinite' }
            : {}),
        }}
      />
      {cfg.label}
    </span>
  );
}
