interface ConfidenceGaugeProps {
  value: number; // 0-100
  size?: number;
}

function getColor(val: number): string {
  if (val >= 70) return 'var(--success)';
  if (val >= 40) return 'var(--warning)';
  return 'var(--danger)';
}

const s = {
  root: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
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
  text: {
    fontSize: '11px',
    color: 'var(--text-secondary)',
  } as React.CSSProperties,
};

export default function ConfidenceGauge({ value, size = 52 }: ConfidenceGaugeProps) {
  const clamped = Math.max(0, Math.min(100, value));
  const color = getColor(clamped);
  const strokeWidth = 4;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (clamped / 100) * circumference;

  return (
    <div style={s.root}>
      <div style={{ ...s.ring, width: size, height: size }}>
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          {/* Background ring */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--bg-tertiary)"
            strokeWidth={strokeWidth}
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
            style={{ transition: 'stroke-dashoffset 0.5s ease, stroke 0.3s ease' }}
          />
        </svg>
        <span
          style={{
            ...s.label,
            fontSize: size > 48 ? '13px' : '10px',
            color,
          }}
        >
          {clamped}%
        </span>
      </div>
      <div style={s.text}>
        {clamped >= 70
          ? 'High confidence'
          : clamped >= 40
            ? 'Moderate confidence'
            : 'Low confidence'}
      </div>
    </div>
  );
}
