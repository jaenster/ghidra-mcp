/**
 * Logger class for structured logging in the daemon
 */

import type { LogLevel, LogEntry } from '@ghidra-mcp/shared';
import { LOG_LEVEL_PRIORITY } from '@ghidra-mcp/shared';
import type { LogStore } from './store.js';

export interface LoggerOptions {
  component: string;
  store: LogStore;
  sessionId?: string;
  workerId?: string;
  minLevel?: LogLevel;
}

export class Logger {
  private readonly component: string;
  readonly store: LogStore;
  private readonly sessionId?: string;
  private readonly workerId?: string;
  private minLevel: LogLevel;

  constructor(options: LoggerOptions) {
    this.component = options.component;
    this.store = options.store;
    this.sessionId = options.sessionId;
    this.workerId = options.workerId;
    this.minLevel = options.minLevel ?? 'INFO';
  }

  /**
   * Set the minimum log level
   */
  setLevel(level: LogLevel): void {
    this.minLevel = level;
  }

  /**
   * Log an error message
   */
  error(message: string, metadata?: Record<string, unknown>): void {
    this.log('ERROR', message, metadata);
  }

  /**
   * Log a warning message
   */
  warn(message: string, metadata?: Record<string, unknown>): void {
    this.log('WARN', message, metadata);
  }

  /**
   * Log an info message
   */
  info(message: string, metadata?: Record<string, unknown>): void {
    this.log('INFO', message, metadata);
  }

  /**
   * Log a debug message
   */
  debug(message: string, metadata?: Record<string, unknown>): void {
    this.log('DEBUG', message, metadata);
  }

  /**
   * Create a child logger with additional context
   */
  child(options: { sessionId?: string; workerId?: string; component?: string }): Logger {
    return new Logger({
      component: options.component ?? this.component,
      store: this.store,
      sessionId: options.sessionId ?? this.sessionId,
      workerId: options.workerId ?? this.workerId,
      minLevel: this.minLevel,
    });
  }

  /**
   * Internal log method
   */
  private log(level: LogLevel, message: string, metadata?: Record<string, unknown>): void {
    // Check if we should log at this level
    if (LOG_LEVEL_PRIORITY[level] > LOG_LEVEL_PRIORITY[this.minLevel]) {
      return;
    }

    const entry: LogEntry = {
      timestamp: Date.now(),
      level,
      source: 'daemon',
      component: this.component,
      sessionId: this.sessionId,
      workerId: this.workerId,
      message,
      metadata,
    };

    // Store the log entry
    this.store.append(entry);

    // Also output to console for backwards compatibility and debugging
    this.consoleOutput(entry);
  }

  /**
   * Output to console in a formatted way
   */
  private consoleOutput(entry: LogEntry): void {
    const timestamp = new Date(entry.timestamp).toISOString();
    const prefix = `[${timestamp}][${entry.component}][${entry.level}]`;

    let contextParts: string[] = [];
    if (entry.sessionId) {
      contextParts.push(`session=${entry.sessionId.slice(0, 8)}`);
    }
    if (entry.workerId) {
      contextParts.push(`worker=${entry.workerId.slice(0, 8)}`);
    }

    const context = contextParts.length > 0 ? ` (${contextParts.join(', ')})` : '';
    const metadataStr = entry.metadata ? ` ${JSON.stringify(entry.metadata)}` : '';

    const output = `${prefix}${context} ${entry.message}${metadataStr}`;

    switch (entry.level) {
      case 'ERROR':
        console.error(output);
        break;
      case 'WARN':
        console.warn(output);
        break;
      case 'DEBUG':
        console.debug(output);
        break;
      default:
        console.log(output);
    }
  }
}

/**
 * Create a root logger for the daemon
 */
export function createLogger(store: LogStore, component: string): Logger {
  return new Logger({
    component,
    store,
    minLevel: process.env.LOG_LEVEL as LogLevel ?? 'INFO',
  });
}
