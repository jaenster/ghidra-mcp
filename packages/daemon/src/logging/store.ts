/**
 * Log storage with per-session indexing and rolling buffer
 */

import type {
  LogEntry,
  LogLevel,
  LogQueryOptions,
  LogQueryResult,
} from '@ghidra-mcp/shared';
import { shouldLog } from '@ghidra-mcp/shared';

export interface LogStoreOptions {
  maxLogs?: number;         // Maximum number of logs to retain (default: 10000)
  maxLogsPerSession?: number; // Maximum logs per session (default: 1000)
}

export class LogStore {
  private logs: LogEntry[] = [];
  private bySession = new Map<string, LogEntry[]>();
  private byWorker = new Map<string, LogEntry[]>();
  private readonly maxLogs: number;
  private readonly maxLogsPerSession: number;

  constructor(options: LogStoreOptions = {}) {
    this.maxLogs = options.maxLogs ?? 10000;
    this.maxLogsPerSession = options.maxLogsPerSession ?? 1000;
  }

  /**
   * Append a log entry to the store
   */
  append(entry: LogEntry): void {
    // Add to main log
    this.logs.push(entry);

    // Trim main log if over limit
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }

    // Index by session
    if (entry.sessionId) {
      let sessionLogs = this.bySession.get(entry.sessionId);
      if (!sessionLogs) {
        sessionLogs = [];
        this.bySession.set(entry.sessionId, sessionLogs);
      }
      sessionLogs.push(entry);

      // Trim session logs if over limit
      if (sessionLogs.length > this.maxLogsPerSession) {
        this.bySession.set(
          entry.sessionId,
          sessionLogs.slice(-this.maxLogsPerSession)
        );
      }
    }

    // Index by worker
    if (entry.workerId) {
      let workerLogs = this.byWorker.get(entry.workerId);
      if (!workerLogs) {
        workerLogs = [];
        this.byWorker.set(entry.workerId, workerLogs);
      }
      workerLogs.push(entry);

      // Trim worker logs if over limit
      if (workerLogs.length > this.maxLogsPerSession) {
        this.byWorker.set(
          entry.workerId,
          workerLogs.slice(-this.maxLogsPerSession)
        );
      }
    }
  }

  /**
   * Append multiple log entries
   */
  appendAll(entries: LogEntry[]): void {
    for (const entry of entries) {
      this.append(entry);
    }
  }

  /**
   * Query logs with filtering and pagination
   */
  query(options: LogQueryOptions = {}): LogQueryResult {
    const {
      sessionId,
      workerId,
      level = 'INFO',
      component,
      since,
      until,
      limit = 100,
      offset = 0,
    } = options;

    // Start with the appropriate source
    let source: LogEntry[];
    if (sessionId && this.bySession.has(sessionId)) {
      source = this.bySession.get(sessionId)!;
    } else if (workerId && this.byWorker.has(workerId)) {
      source = this.byWorker.get(workerId)!;
    } else {
      source = this.logs;
    }

    // Filter entries
    const filtered = source.filter((entry) => {
      // Level filter - include entries at or above the specified level
      if (!shouldLog(entry.level, level)) {
        return false;
      }

      // Component filter
      if (component && entry.component !== component) {
        return false;
      }

      // Session filter (if not already filtered by session index)
      if (sessionId && !this.bySession.has(sessionId) && entry.sessionId !== sessionId) {
        return false;
      }

      // Worker filter (if not already filtered by worker index)
      if (workerId && !this.byWorker.has(workerId) && entry.workerId !== workerId) {
        return false;
      }

      // Time range filter
      if (since !== undefined && entry.timestamp < since) {
        return false;
      }
      if (until !== undefined && entry.timestamp > until) {
        return false;
      }

      return true;
    });

    const total = filtered.length;
    const hasMore = offset + limit < total;

    // Apply pagination (return most recent first)
    const entries = filtered
      .slice()
      .reverse()
      .slice(offset, offset + limit);

    return {
      entries,
      total,
      hasMore,
    };
  }

  /**
   * Get logs for a specific session
   */
  getSessionLogs(sessionId: string, limit = 100): LogEntry[] {
    const sessionLogs = this.bySession.get(sessionId);
    if (!sessionLogs) {
      return [];
    }
    return sessionLogs.slice(-limit).reverse();
  }

  /**
   * Get logs for a specific worker
   */
  getWorkerLogs(workerId: string, limit = 100): LogEntry[] {
    const workerLogs = this.byWorker.get(workerId);
    if (!workerLogs) {
      return [];
    }
    return workerLogs.slice(-limit).reverse();
  }

  /**
   * Get recent logs
   */
  getRecent(limit = 100): LogEntry[] {
    return this.logs.slice(-limit).reverse();
  }

  /**
   * Clear all logs
   */
  clear(): void {
    this.logs = [];
    this.bySession.clear();
    this.byWorker.clear();
  }

  /**
   * Clear logs for a specific session
   */
  clearSession(sessionId: string): void {
    this.bySession.delete(sessionId);
    this.logs = this.logs.filter((entry) => entry.sessionId !== sessionId);
  }

  /**
   * Clear logs for a specific worker
   */
  clearWorker(workerId: string): void {
    this.byWorker.delete(workerId);
    this.logs = this.logs.filter((entry) => entry.workerId !== workerId);
  }

  /**
   * Get statistics about the log store
   */
  getStats(): { total: number; sessions: number; workers: number } {
    return {
      total: this.logs.length,
      sessions: this.bySession.size,
      workers: this.byWorker.size,
    };
  }
}
