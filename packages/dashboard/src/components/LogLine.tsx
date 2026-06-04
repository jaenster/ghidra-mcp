const LEVEL_COLORS: Record<string, string> = {
  error: '#ef4444',
  warn: '#f59e0b',
  info: '#3b82f6',
  debug: '#6b7280',
};

interface LogEntry {
  timestamp: number;
  level: string;
  component?: string;
  message: string;
}

export function LogLine({ entry }: { entry: LogEntry }) {
  const time = new Date(entry.timestamp).toLocaleTimeString();
  const color = LEVEL_COLORS[entry.level] ?? '#ccc';

  return (
    <div style={{ fontFamily: 'monospace', fontSize: 12, padding: '2px 0', borderBottom: '1px solid #222' }}>
      <span style={{ color: '#666', marginRight: 8 }}>{time}</span>
      <span style={{ color, fontWeight: 600, marginRight: 8, textTransform: 'uppercase', width: 40, display: 'inline-block' }}>
        {entry.level}
      </span>
      {entry.component && (
        <span style={{ color: '#888', marginRight: 8 }}>[{entry.component}]</span>
      )}
      <span style={{ color: '#ddd' }}>{entry.message}</span>
    </div>
  );
}
