/**
 * Command history ring buffer for dashboard
 */

export interface CommandLogEntry {
  id: string;
  sessionId: string;
  command: string;
  params: Record<string, unknown>;
  startedAt: number;
  completedAt?: number;
  duration?: number;
  success?: boolean;
  error?: string;
}

const MAX_ENTRIES = 1000;

// Fields to strip from params to keep entries small
const STRIP_FIELDS = new Set(['code', 'filePath', '_programPath']);

function stripParams(params: Record<string, unknown>): Record<string, unknown> {
  const stripped: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(params)) {
    if (STRIP_FIELDS.has(key)) continue;
    if (typeof value === 'string' && value.length > 200) {
      stripped[key] = value.slice(0, 200) + '...';
    } else {
      stripped[key] = value;
    }
  }
  return stripped;
}

export class CommandLog {
  private entries: CommandLogEntry[] = [];
  private listeners: Array<(event: string, entry: CommandLogEntry) => void> = [];

  recordStart(id: string, sessionId: string, command: string, params: Record<string, unknown>): void {
    const entry: CommandLogEntry = {
      id,
      sessionId,
      command,
      params: stripParams(params),
      startedAt: Date.now(),
    };

    this.entries.push(entry);
    if (this.entries.length > MAX_ENTRIES) {
      this.entries.shift();
    }

    this.emit('command:start', entry);
  }

  recordComplete(id: string, success: boolean, error?: string): void {
    const entry = this.entries.find(e => e.id === id);
    if (!entry) return;

    entry.completedAt = Date.now();
    entry.duration = entry.completedAt - entry.startedAt;
    entry.success = success;
    entry.error = error;

    this.emit('command:complete', entry);
  }

  getRecent(limit: number = 100): CommandLogEntry[] {
    return this.entries.slice(-limit);
  }

  onEvent(listener: (event: string, entry: CommandLogEntry) => void): () => void {
    this.listeners.push(listener);
    return () => {
      const idx = this.listeners.indexOf(listener);
      if (idx >= 0) this.listeners.splice(idx, 1);
    };
  }

  private emit(event: string, entry: CommandLogEntry): void {
    for (const listener of this.listeners) {
      try {
        listener(event, entry);
      } catch {
        // ignore listener errors
      }
    }
  }
}
