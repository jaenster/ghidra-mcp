interface CommandEntry {
  id: string;
  sessionId: string;
  command: string;
  startedAt: number;
  completedAt?: number;
  duration?: number;
  success?: boolean;
  error?: string;
}

export function CommandRow({ entry }: { entry: CommandEntry }) {
  const time = new Date(entry.startedAt).toLocaleTimeString();
  const dur = entry.duration != null ? `${entry.duration}ms` : '...';
  const statusColor = entry.success === true ? '#22c55e' : entry.success === false ? '#ef4444' : '#f59e0b';

  return (
    <tr style={{ borderBottom: '1px solid #333' }}>
      <td style={{ padding: '4px 8px', color: '#888', fontSize: 12 }}>{time}</td>
      <td style={{ padding: '4px 8px', fontFamily: 'monospace', fontSize: 13 }}>{entry.command}</td>
      <td style={{ padding: '4px 8px', color: '#888', fontSize: 12 }}>{entry.sessionId.slice(0, 8)}</td>
      <td style={{ padding: '4px 8px', color: statusColor, fontSize: 12, fontWeight: 600 }}>{dur}</td>
      <td style={{ padding: '4px 8px', color: '#ef4444', fontSize: 11 }}>{entry.error ?? ''}</td>
    </tr>
  );
}
