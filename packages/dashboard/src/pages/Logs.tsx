import { useState, useRef, useEffect, useCallback } from 'react';
import { fetchLogs } from '../api';
import { useSse } from '../hooks/useSse';
import { LogLine } from '../components/LogLine';

export function Logs() {
  const [entries, setEntries] = useState<any[]>([]);
  const [level, setLevel] = useState<string>('');
  const [component, setComponent] = useState<string>('');
  const bottomRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Initial load
  useEffect(() => {
    fetchLogs({ limit: 200, level: level || undefined, component: component || undefined })
      .then(data => setEntries(data.entries ?? []))
      .catch(() => {});
  }, [level, component]);

  // Live updates
  useSse('/api/dashboard/events', {
    log: useCallback((data: unknown) => {
      const entry = data as any;
      if (level && entry.level !== level) return;
      if (component && entry.component !== component) return;
      setEntries(prev => {
        const next = [...prev, entry];
        return next.length > 500 ? next.slice(-500) : next;
      });
    }, [level, component]),
  });

  // Auto-scroll
  useEffect(() => {
    if (autoScroll) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [entries, autoScroll]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 100px)' }}>
      <div style={{ display: 'flex', gap: 12, marginBottom: 12, alignItems: 'center' }}>
        <h2 style={{ margin: 0 }}>Logs</h2>
        <select value={level} onChange={e => setLevel(e.target.value)} style={selectStyle}>
          <option value="">All levels</option>
          <option value="error">Error</option>
          <option value="warn">Warn</option>
          <option value="info">Info</option>
          <option value="debug">Debug</option>
        </select>
        <input
          type="text"
          placeholder="Component..."
          value={component}
          onChange={e => setComponent(e.target.value)}
          style={inputStyle}
        />
        <label style={{ fontSize: 12, color: '#888' }}>
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={e => setAutoScroll(e.target.checked)}
          />{' '}
          Auto-scroll
        </label>
      </div>
      <div style={{ flex: 1, overflow: 'auto', background: '#0d0d1a', padding: 8, borderRadius: 8 }}>
        {entries.map((e, i) => (
          <LogLine key={`${e.timestamp}-${i}`} entry={e} />
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

const selectStyle = {
  background: '#1a1a2e',
  color: '#ddd',
  border: '1px solid #333',
  borderRadius: 4,
  padding: '4px 8px',
  fontSize: 13,
} as const;

const inputStyle = {
  background: '#1a1a2e',
  color: '#ddd',
  border: '1px solid #333',
  borderRadius: 4,
  padding: '4px 8px',
  fontSize: 13,
  width: 150,
} as const;
