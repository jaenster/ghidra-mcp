import { useState, useCallback } from 'react';
import { usePolling } from '../hooks/usePolling';
import { useSse } from '../hooks/useSse';
import { fetchCommands } from '../api';
import { CommandRow } from '../components/CommandRow';

export function Commands() {
  const { data: commands, refresh } = usePolling(fetchCommands, 5000);

  // Live updates via SSE
  useSse('/api/dashboard/events', {
    'command:start': () => refresh(),
    'command:complete': () => refresh(),
  });

  return (
    <div>
      <h2>Command History</h2>
      {commands && commands.length > 0 ? (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #444', textAlign: 'left' }}>
              <th style={th}>Time</th>
              <th style={th}>Command</th>
              <th style={th}>Session</th>
              <th style={th}>Duration</th>
              <th style={th}>Error</th>
            </tr>
          </thead>
          <tbody>
            {[...commands].reverse().map((cmd: any) => (
              <CommandRow key={cmd.id} entry={cmd} />
            ))}
          </tbody>
        </table>
      ) : (
        <p style={{ color: '#888' }}>No commands yet</p>
      )}
    </div>
  );
}

const th = { padding: '4px 8px', color: '#888', fontSize: 12 } as const;
