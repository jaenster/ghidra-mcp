package com.ghidramcp.logging;

import com.google.gson.Gson;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Logger for the Ghidra worker that streams logs to the daemon via WebSocket.
 * Logs are also printed to stdout for backwards compatibility and local debugging.
 */
public class Logger {

    public enum Level {
        ERROR(0),
        WARN(1),
        INFO(2),
        DEBUG(3);

        private final int priority;

        Level(int priority) {
            this.priority = priority;
        }

        public int getPriority() {
            return priority;
        }
    }

    private static final Gson gson = new Gson();
    private static final Object pendingLock = new Object();
    private static final List<LogEntry> pending = new ArrayList<>();
    private static WebSocket webSocket;
    private static ScheduledExecutorService flushScheduler;
    private static boolean initialized = false;
    private static String globalWorkerId;
    private static String globalSessionId;

    private final String component;
    private final String sessionId;
    private final String workerId;
    private Level minLevel = Level.INFO;

    /**
     * Create a new Logger instance.
     */
    public Logger(String component, String workerId, String sessionId) {
        this.component = component;
        this.workerId = workerId;
        this.sessionId = sessionId;
    }

    /**
     * Initialize the WebSocket connection to the daemon.
     * Should be called once at worker startup.
     */
    public static void initWebSocket(String daemonUrl, String workerId, String sessionId) {
        if (initialized) {
            return;
        }

        globalWorkerId = workerId;
        globalSessionId = sessionId;

        try {
            // Convert http:// to ws:// or https:// to wss://
            String secret = System.getenv("GHIDRA_MCP_WORKER_SECRET");
            String wsUrl = daemonUrl.replace("http://", "ws://").replace("https://", "wss://")
                    + "/internal/ws/logs?workerId=" + workerId
                    + (secret != null ? "&secret=" + java.net.URLEncoder.encode(secret, java.nio.charset.StandardCharsets.UTF_8) : "");

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();

            webSocket = client.newWebSocketBuilder()
                    .buildAsync(URI.create(wsUrl), new LogWebSocketListener())
                    .join();

            // Start flush thread (every 100ms)
            flushScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "log-flush-thread");
                t.setDaemon(true);
                return t;
            });
            flushScheduler.scheduleAtFixedRate(Logger::flush, 100, 100, TimeUnit.MILLISECONDS);

            initialized = true;
            System.out.println("[Logger] WebSocket logging initialized");
        } catch (Exception e) {
            System.err.println("[Logger] Failed to initialize WebSocket logging: " + e.getMessage());
            // Continue without WebSocket - logs will still go to stdout
        }
    }

    /**
     * Shutdown the WebSocket connection and flush remaining logs.
     */
    public static void shutdown() {
        if (flushScheduler != null) {
            flushScheduler.shutdown();
            try {
                flushScheduler.awaitTermination(1, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        // Final flush
        flush();

        if (webSocket != null) {
            webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "shutdown");
        }

        initialized = false;
    }

    /**
     * Create a root logger instance.
     */
    public static Logger create(String component, String workerId, String sessionId) {
        return new Logger(component, workerId, sessionId);
    }

    /**
     * Set the minimum log level.
     */
    public void setLevel(Level level) {
        this.minLevel = level;
    }

    /**
     * Create a child logger with a different component name.
     */
    public Logger child(String childComponent) {
        Logger child = new Logger(childComponent, this.workerId, this.sessionId);
        child.minLevel = this.minLevel;
        return child;
    }

    /**
     * Log an error message.
     */
    public void error(String message) {
        log(Level.ERROR, message, null);
    }

    /**
     * Log an error message with metadata.
     */
    public void error(String message, Map<String, Object> metadata) {
        log(Level.ERROR, message, metadata);
    }

    /**
     * Log a warning message.
     */
    public void warn(String message) {
        log(Level.WARN, message, null);
    }

    /**
     * Log a warning message with metadata.
     */
    public void warn(String message, Map<String, Object> metadata) {
        log(Level.WARN, message, metadata);
    }

    /**
     * Log an info message.
     */
    public void info(String message) {
        log(Level.INFO, message, null);
    }

    /**
     * Log an info message with metadata.
     */
    public void info(String message, Map<String, Object> metadata) {
        log(Level.INFO, message, metadata);
    }

    /**
     * Log a debug message.
     */
    public void debug(String message) {
        log(Level.DEBUG, message, null);
    }

    /**
     * Log a debug message with metadata.
     */
    public void debug(String message, Map<String, Object> metadata) {
        log(Level.DEBUG, message, metadata);
    }

    /**
     * Internal log method.
     */
    private void log(Level level, String message, Map<String, Object> metadata) {
        if (level.getPriority() > minLevel.getPriority()) {
            return;
        }

        LogEntry entry = new LogEntry();
        entry.timestamp = System.currentTimeMillis();
        entry.level = level.name();
        entry.source = "worker";
        entry.component = component;
        entry.sessionId = sessionId;
        entry.workerId = workerId;
        entry.message = message;
        entry.metadata = metadata;

        // Add to pending queue for WebSocket transmission
        synchronized (pendingLock) {
            pending.add(entry);
        }

        // Also print to stdout (backwards compat + local debugging)
        printToConsole(entry);
    }

    /**
     * Print a log entry to the console.
     */
    private void printToConsole(LogEntry entry) {
        String prefix = String.format("[%s][%s]", entry.component, entry.level);
        String metaStr = entry.metadata != null ? " " + gson.toJson(entry.metadata) : "";
        String output = prefix + " " + entry.message + metaStr;

        if ("ERROR".equals(entry.level)) {
            System.err.println(output);
        } else {
            System.out.println(output);
        }
    }

    /**
     * Flush pending logs to the WebSocket.
     */
    private static void flush() {
        List<LogEntry> toSend;
        synchronized (pendingLock) {
            if (pending.isEmpty()) {
                return;
            }
            toSend = new ArrayList<>(pending);
            pending.clear();
        }

        if (webSocket != null) {
            try {
                String json = gson.toJson(toSend);
                webSocket.sendText(json, true);
            } catch (Exception e) {
                // Log to stderr but don't throw - we don't want logging to crash the worker
                System.err.println("[Logger] Failed to send logs: " + e.getMessage());
            }
        }
    }

    /**
     * WebSocket listener for the log connection.
     */
    private static class LogWebSocketListener implements WebSocket.Listener {
        @Override
        public void onOpen(WebSocket ws) {
            System.out.println("[Logger] WebSocket connection opened");
        }

        @Override
        public CompletionStage<?> onClose(WebSocket ws, int statusCode, String reason) {
            System.out.println("[Logger] WebSocket connection closed: " + statusCode + " - " + reason);
            return null;
        }

        @Override
        public void onError(WebSocket ws, Throwable error) {
            System.err.println("[Logger] WebSocket error: " + error.getMessage());
        }

        @Override
        public CompletionStage<?> onText(WebSocket ws, CharSequence data, boolean last) {
            // We don't expect to receive messages, but request more if we do
            ws.request(1);
            return null;
        }
    }
}
