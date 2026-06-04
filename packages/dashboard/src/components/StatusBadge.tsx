const COLORS: Record<string, string> = {
  idle: '#22c55e',
  busy: '#f59e0b',
  starting: '#3b82f6',
  stopping: '#6b7280',
  stopped: '#ef4444',
  ready: '#22c55e',
  error: '#ef4444',
  creating: '#3b82f6',
};

export function StatusBadge({ status }: { status: string }) {
  const color = COLORS[status] ?? '#6b7280';
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: 12,
      fontWeight: 600,
      color: '#fff',
      background: color,
    }}>
      {status}
    </span>
  );
}
