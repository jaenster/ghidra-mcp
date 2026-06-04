import { useEffect, useRef, useCallback, useState } from 'react';

type EventHandler = (data: unknown) => void;

export function useSse(
  url: string,
  eventHandlers: Record<string, EventHandler>
): { connected: boolean } {
  const [connected, setConnected] = useState(false);
  const esRef = useRef<EventSource | null>(null);
  const handlersRef = useRef(eventHandlers);
  handlersRef.current = eventHandlers;

  useEffect(() => {
    const es = new EventSource(url);
    esRef.current = es;

    es.addEventListener('connected', () => setConnected(true));
    es.onerror = () => setConnected(false);

    for (const event of Object.keys(handlersRef.current)) {
      es.addEventListener(event, (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data);
          handlersRef.current[event]?.(data);
        } catch {
          // ignore parse errors
        }
      });
    }

    return () => {
      es.close();
      setConnected(false);
    };
  }, [url]);

  return { connected };
}
