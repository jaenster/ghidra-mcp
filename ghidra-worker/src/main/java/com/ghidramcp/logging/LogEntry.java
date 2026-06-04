package com.ghidramcp.logging;

import java.util.Map;

/**
 * Log entry data structure matching the TypeScript LogEntry interface.
 */
public class LogEntry {
    public long timestamp;
    public String level;
    public String source;
    public String component;
    public String sessionId;
    public String workerId;
    public String message;
    public Map<String, Object> metadata;

    public LogEntry() {
    }

    public LogEntry(long timestamp, String level, String source, String component,
                    String sessionId, String workerId, String message, Map<String, Object> metadata) {
        this.timestamp = timestamp;
        this.level = level;
        this.source = source;
        this.component = component;
        this.sessionId = sessionId;
        this.workerId = workerId;
        this.message = message;
        this.metadata = metadata;
    }
}
