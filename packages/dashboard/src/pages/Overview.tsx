import { usePolling } from '../hooks/usePolling';
import { fetchHealth, fetchSessions } from '../api';
import { StatusBadge } from '../components/StatusBadge';

export function Overview() {
  const { data: health } = usePolling(fetchHealth, 5000);
  const { data: sessions } = usePolling(fetchSessions, 5000);

  return (
    <div>
      <h2>Overview</h2>

      {health && (
        <div style={{ display: 'flex', gap: 24, marginBottom: 24 }}>
          <StatCard label="Uptime" value={formatUptime(health.uptime)} />
          <StatCard label="Sessions" value={health.sessions} />
          <StatCard label="Workers" value={health.workers} />
        </div>
      )}

      <h3>Sessions</h3>
      {sessions && sessions.length > 0 ? (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #444', textAlign: 'left' }}>
              <th style={th}>ID</th>
              <th style={th}>Status</th>
              <th style={th}>Binary</th>
              <th style={th}>Created</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s: any) => (
              <tr key={s.id} style={{ borderBottom: '1px solid #333' }}>
                <td style={td}>{s.id.slice(0, 8)}</td>
                <td style={td}><StatusBadge status={s.status} /></td>
                <td style={td}>{s.binaryPath?.split('/').pop() ?? '--'}</td>
                <td style={td}>{new Date(s.createdAt).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p style={{ color: '#888' }}>No sessions</p>
      )}
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div style={{
      background: '#1a1a2e',
      padding: '16px 24px',
      borderRadius: 8,
      minWidth: 120,
    }}>
      <div style={{ color: '#888', fontSize: 12, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 700 }}>{value}</div>
    </div>
  );
}

function formatUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

const th = { padding: '8px', color: '#888', fontSize: 12 } as const;
const td = { padding: '8px', fontSize: 13 } as const;
