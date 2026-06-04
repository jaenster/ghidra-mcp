/**
 * Simple SVG sparkline for memory usage over time.
 */
export function MemoryChart({ samples, width = 120, height = 30 }: {
  samples: number[];
  width?: number;
  height?: number;
}) {
  if (samples.length < 2) {
    return <span style={{ color: '#888', fontSize: 12 }}>--</span>;
  }

  const max = Math.max(...samples, 1);
  const points = samples.map((v, i) => {
    const x = (i / (samples.length - 1)) * width;
    const y = height - (v / max) * height;
    return `${x},${y}`;
  }).join(' ');

  const lastMb = (samples[samples.length - 1] / (1024 * 1024)).toFixed(0);

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <svg width={width} height={height} style={{ background: '#1a1a2e', borderRadius: 4 }}>
        <polyline
          points={points}
          fill="none"
          stroke="#3b82f6"
          strokeWidth={1.5}
        />
      </svg>
      <span style={{ fontSize: 12, color: '#ccc' }}>{lastMb}MB</span>
    </span>
  );
}
