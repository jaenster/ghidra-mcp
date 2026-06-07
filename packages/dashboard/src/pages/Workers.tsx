import { useMemo, useState } from 'react';
import { usePolling } from '../hooks/usePolling';
import { useSse } from '../hooks/useSse';
import { fetchWorkers, killWorker } from '../api';
import { StatusBadge } from '../components/StatusBadge';
import { MemoryChart } from '../components/MemoryChart';

function ThreadPool({ threads }: { threads?: { readPoolSize: number; readPoolActive: number; currentCommands: Record<string, string> } }) {
  if (!threads) return <span style={{ color: '#555' }}>--</span>;

  const slots = useMemo(() => {
    const result: Array<{ name: string; command: string | null }> = [];
    for (let i = 1; i <= threads.readPoolSize; i++) {
      const name = `cmd-read-pool-${i}`;
      result.push({ name, command: threads.currentCommands[name] ?? null });
    }
    return result;
  }, [threads]);

  return (
    <div style={{ display: 'flex', gap: 3, alignItems: 'center' }}>
      {slots.map(slot => (
        <div
          key={slot.name}
          title={slot.command ? `${slot.name}: ${slot.command}` : `${slot.name}: idle`}
          style={{
            width: 10,
            height: 10,
            borderRadius: 2,
            background: slot.command ? '#4ade80' : '#333',
            border: '1px solid #555',
            cursor: 'default',
          }}
        />
      ))}
      {threads.readPoolActive > 0 && (
        <span style={{ fontSize: 11, color: '#888', marginLeft: 4 }}>
          {Object.values(threads.currentCommands).join(', ')}
        </span>
      )}
    </div>
  );
}

export function Workers() {
  const { data: workers, refresh } = usePolling(fetchWorkers, 5000);
  const [killing, setKilling] = useState<string | null>(null);

  // Also listen for heartbeat events to update more frequently
  useSse('/api/dashboard/events', {
    heartbeat: () => refresh(),
  });

  async function onKill(id: string) {
    if (!window.confirm('Force-kill (unstick) this worker? A fresh one will respawn.')) return;
    setKilling(id);
    try {
      await killWorker(id);
      refresh();
    } catch (e) {
      window.alert(`Failed to kill worker: ${(e as Error).message}`);
    } finally {
      setKilling(null);
    }
  }

  return (
    <div>
      <h2>Workers</h2>
      {workers && workers.length > 0 ? (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #444', textAlign: 'left' }}>
              <th style={th}>ID</th>
              <th style={th}>Session</th>
              <th style={th}>Status</th>
              <th style={th}>PID</th>
              <th style={th}>Commands</th>
              <th style={th}>Threads</th>
              <th style={th}>Memory</th>
              <th style={th}>Last Heartbeat</th>
              <th style={th}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {workers.map((w: any) => (
              <tr key={w.id} style={{ borderBottom: '1px solid #333' }}>
                <td style={td}>{w.id.slice(0, 8)}</td>
                <td style={td}>{w.sessionId.slice(0, 8)}</td>
                <td style={td}><StatusBadge status={w.status} /></td>
                <td style={td}>{w.pid ?? '--'}</td>
                <td style={td}>{w.activeCommands}</td>
                <td style={td}><ThreadPool threads={w.threads} /></td>
                <td style={td}>
                  <MemoryChart samples={w.memorySamples ?? []} />
                </td>
                <td style={td}>
                  {w.lastHeartbeat ? `${Math.round((Date.now() - w.lastHeartbeat) / 1000)}s ago` : '--'}
                </td>
                <td style={td}>
                  <button
                    onClick={() => onKill(w.id)}
                    disabled={killing === w.id}
                    style={actionBtn}
                  >
                    {killing === w.id ? 'Killing…' : 'Unstick'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p style={{ color: '#888' }}>No workers</p>
      )}
    </div>
  );
}

const th = { padding: '8px', color: '#888', fontSize: 12 } as const;
const td = { padding: '8px', fontSize: 13 } as const;
const actionBtn = {
  background: '#3a1a1a',
  color: '#f87171',
  border: '1px solid #663333',
  borderRadius: 4,
  padding: '3px 8px',
  fontSize: 12,
  cursor: 'pointer',
} as const;
