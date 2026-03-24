interface ConfidenceGaugeProps {
  value: number; // 0-100
  size?: number;
}

function getColor(val: number): string {
  if (val >= 70) return 'var(--success)';
  if (val >= 40) return 'var(--warning)';
  return 'var(--danger)';
}

function getLabel(val: number): string {
  if (val >= 70) return 'High confidence';
  if (val >= 40) return 'Moderate';
  return 'Low confidence';
}

const s = {
  root: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  } as React.CSSProperties,
  ring: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  } as React.CSSProperties,
  label: {
    position: 'absolute',
    fontFamily: 'var(--font-mono)',
    fontWeight: 700,
    letterSpacing: '-0.02em',
  } as React.CSSProperties,
  halo: {
    position: 'absolute',
    inset: '18%',
    borderRadius: '50%',
    filter: 'blur(12px)',
    opacity: 0.32,
    pointerEvents: 'none',
  } as React.CSSProperties,
  meta: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
  } as React.CSSProperties,
  labelText: {
    fontSize: '11px',
    fontWeight: 500,
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
  subtext: {
    fontSize: '10px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
  } as React.CSSProperties,
};

export default function ConfidenceGauge({ value, size = 56 }: ConfidenceGaugeProps) {
  const clamped = Math.max(0, Math.min(100, value));
  const color = getColor(clamped);
  const strokeWidth = 4;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (clamped / 100) * circumference;

  return (
    <div style={s.root}>
      <div style={{ ...s.ring, width: size, height: size }}>
        <div style={{ ...s.halo, background: color }} />
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius + 5}
            fill="none"
            stroke={color}
            strokeWidth={1}
            strokeDasharray="2 8"
            opacity={0.18}
          />
          {/* Background ring */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--bg-tertiary)"
            strokeWidth={strokeWidth}
          />
          {/* Glow behind progress */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth + 4}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            opacity={0.15}
            style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.3s ease' }}
          />
          {/* Progress ring */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.3s ease' }}
          />
        </svg>
        <span
          style={{
            ...s.label,
            fontSize: size > 48 ? '14px' : '10px',
            color,
            textShadow: `0 0 12px ${color}33`,
          }}
        >
          {clamped}%
        </span>
      </div>
      <div style={s.meta as React.CSSProperties}>
        <span style={s.labelText}>{getLabel(clamped)}</span>
        <span style={s.subtext}>{clamped}/100 overall</span>
      </div>
    </div>
  );
}
