package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * HTTP client for communicating with the Node.js daemon.
 */
public class DaemonClient {
    private static final Gson gson = new GsonBuilder().serializeNulls().create();

    private final String daemonUrl;
    private String workerId;  // non-final: updated on reconnect
    private final String sessionId;
    private final Logger log;
    // Shared secret authenticating /internal/* calls; supplied by the daemon via env.
    private static final String WORKER_SECRET = System.getenv("GHIDRA_MCP_WORKER_SECRET");
    private final int pollTimeout = 10000; // 10 seconds (must be > server's 5s long-poll timeout)
    private volatile long lastHeartbeat = 0;
    private final long heartbeatInterval = 5000; // 5 seconds
    private final AtomicReference<String> heartbeatStatus = new AtomicReference<>("idle");
    private volatile boolean heartbeatRunning = false;
    private Thread heartbeatThread;
    private volatile Supplier<JsonObject> heartbeatExtraSupplier;

    public DaemonClient(String daemonUrl, String workerId, String sessionId, Logger log) {
        this.daemonUrl = daemonUrl;
        this.workerId = workerId;
        this.sessionId = sessionId;
        this.log = log;
    }

    /**
     * Start background heartbeat thread. Sends heartbeats every 5s regardless of
     * whether the main command loop is blocked (e.g., during long decompilations).
     */
    public void startHeartbeatThread() {
        heartbeatRunning = true;
        heartbeatThread = new Thread(() -> {
            while (heartbeatRunning) {
                try {
                    Supplier<JsonObject> supplier = heartbeatExtraSupplier;
                    JsonObject extra = supplier != null ? supplier.get() : null;
                    sendHeartbeatNow(heartbeatStatus.get(), extra);
                } catch (Exception e) {
                    // Swallow — heartbeat failures are non-fatal
                }
                try {
                    Thread.sleep(heartbeatInterval);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "heartbeat");
        heartbeatThread.setDaemon(true);
        heartbeatThread.start();
    }

    public void stopHeartbeatThread() {
        heartbeatRunning = false;
        if (heartbeatThread != null) {
            heartbeatThread.interrupt();
        }
    }

    public void setHeartbeatStatus(String status) {
        heartbeatStatus.set(status);
    }

    /**
     * Set a supplier for extra heartbeat payload (e.g. thread status from CommandDispatcher).
     */
    public void setHeartbeatExtraSupplier(Supplier<JsonObject> supplier) {
        this.heartbeatExtraSupplier = supplier;
    }

    /**
     * Check if the daemon is reachable before doing heavy initialization
     */
    public void checkConnection() throws IOException {
        try {
            URL url = new URL(daemonUrl + "/health");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                throw new IOException("Daemon health check failed: HTTP " + responseCode);
            }

            // Read and discard response
            try (InputStream is = conn.getInputStream()) {
                is.readAllBytes();
            }

            log.info("Daemon connection verified");
        } catch (IOException e) {
            throw new IOException("Cannot connect to daemon at " + daemonUrl + ": " + e.getMessage(), e);
        }
    }

    /**
     * Register with the daemon
     */
    public void register() throws IOException {
        JsonObject registration = new JsonObject();
        registration.addProperty("workerId", workerId);
        registration.addProperty("sessionId", sessionId);
        registration.addProperty("pid", ProcessHandle.current().pid());
        registration.addProperty("startTime", System.currentTimeMillis());

        post("/internal/worker/" + workerId + "/register", registration);
    }

    /**
     * Poll for the next command
     */
    public JsonObject pollCommand() throws IOException {
        String response = get("/internal/worker/" + workerId + "/command", pollTimeout);
        if (response == null || response.isEmpty() || "null".equals(response)) {
            return null;
        }
        return gson.fromJson(response, JsonObject.class);
    }

    /**
     * Send a command result back to the daemon
     */
    public void sendResult(String commandId, boolean success, JsonObject result, String error)
            throws IOException {
        int resultSize = result != null ? gson.toJson(result).length() : 0;
        log.debug("Posting result: id=" + commandId + " success=" + success + " resultSize=" + resultSize);
        JsonObject response = new JsonObject();
        response.addProperty("id", commandId);
        response.addProperty("success", success);

        if (result != null) {
            response.add("result", result);
        }

        if (error != null) {
            JsonObject errorObj = new JsonObject();
            errorObj.addProperty("message", error);
            response.add("error", errorObj);
        }

        post("/internal/worker/" + workerId + "/result", response);
    }

    /**
     * Send a heartbeat to the daemon
     */
    public void heartbeat(String status) throws IOException {
        heartbeat(status, null);
    }

    public void heartbeat(String status, JsonObject extraPayload) throws IOException {
        long now = System.currentTimeMillis();
        if (now - lastHeartbeat < heartbeatInterval) {
            return; // Not time for heartbeat yet
        }
        sendHeartbeatNow(status, extraPayload);
    }

    private synchronized void sendHeartbeatNow(String status, JsonObject extraPayload) {
        long now = System.currentTimeMillis();

        JsonObject heartbeat = new JsonObject();
        heartbeat.addProperty("workerId", workerId);
        heartbeat.addProperty("sessionId", sessionId);
        heartbeat.addProperty("status", status);
        heartbeat.addProperty("uptime", now - getStartTime());

        Runtime runtime = Runtime.getRuntime();
        heartbeat.addProperty("memoryUsed", runtime.totalMemory() - runtime.freeMemory());

        if (extraPayload != null) {
            for (var entry : extraPayload.entrySet()) {
                heartbeat.add(entry.getKey(), entry.getValue());
            }
        }

        try {
            post("/internal/worker/" + workerId + "/heartbeat", heartbeat);
            lastHeartbeat = now;
        } catch (IOException e) {
            log.warn("Heartbeat failed: " + e.getMessage());
        }
    }

    private long startTime = System.currentTimeMillis();
    private long getStartTime() {
        return startTime;
    }

    /**
     * Get the current worker ID (may change after reconnect)
     */
    public String getWorkerId() {
        return workerId;
    }

    /**
     * Check if the daemon is reachable (non-throwing)
     */
    public boolean isDaemonReachable() {
        try {
            URL url = new URL(daemonUrl + "/health");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            conn.setRequestMethod("GET");
            int code = conn.getResponseCode();
            try (InputStream is = conn.getInputStream()) { is.readAllBytes(); }
            return code == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * HTTP POST request that returns the response body
     */
    private String postWithResponse(String path, JsonObject body) throws IOException {
        URL url = new URL(daemonUrl + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        if (WORKER_SECRET != null) conn.setRequestProperty("X-Worker-Secret", WORKER_SECRET);
        conn.setDoOutput(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        byte[] bodyBytes = gson.toJson(body).getBytes(StandardCharsets.UTF_8);
        conn.setRequestProperty("Content-Length", String.valueOf(bodyBytes.length));
        try (OutputStream os = conn.getOutputStream()) { os.write(bodyBytes); }
        int code = conn.getResponseCode();
        if (code != 200) {
            // Read error body for diagnostics
            try (InputStream es = conn.getErrorStream()) {
                String errBody = es != null ? new String(es.readAllBytes(), StandardCharsets.UTF_8) : "";
                throw new IOException("HTTP POST " + path + " failed: " + code + " " + errBody);
            }
        }
        try (InputStream is = conn.getInputStream()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Reconnect to a restarted daemon. Sends session metadata, gets a new workerId back.
     */
    public String reconnectRegister(String binaryPath, String projectPath, boolean readOnly)
            throws IOException {
        JsonObject payload = new JsonObject();
        payload.addProperty("sessionId", sessionId);
        payload.addProperty("binaryPath", binaryPath);
        payload.addProperty("projectPath", projectPath);
        payload.addProperty("readOnly", readOnly);
        payload.addProperty("pid", ProcessHandle.current().pid());

        String response = postWithResponse("/internal/reconnect", payload);
        JsonObject json = gson.fromJson(response, JsonObject.class);

        if (json.has("workerId")) {
            String newWorkerId = json.get("workerId").getAsString();
            this.workerId = newWorkerId;
            return newWorkerId;
        }
        throw new IOException("Reconnect rejected: " + response);
    }

    /**
     * HTTP GET request
     */
    private String get(String path, int timeout) throws IOException {
        URL url = new URL(daemonUrl + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        if (WORKER_SECRET != null) conn.setRequestProperty("X-Worker-Secret", WORKER_SECRET);
        conn.setConnectTimeout(timeout);
        conn.setReadTimeout(timeout);

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            throw new IOException("HTTP GET failed: " + responseCode);
        }

        try (InputStream is = conn.getInputStream()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Push a batch of program changes to the daemon.
     *
     * Retried with a short backoff rather than dropped: a subscriber cannot tell a lost
     * batch from a quiet program, so losing one is worse than being late with it. The
     * journal on disk stays authoritative either way - a batch that never lands is still
     * served by get_changes when the subscriber reconnects.
     */
    public void postChanges(JsonArray events) {
        if (events == null || events.isEmpty()) return;
        JsonObject body = new JsonObject();
        body.addProperty("sessionId", sessionId);
        body.add("events", events);

        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                post("/internal/worker/" + workerId + "/changes", body);
                return;
            } catch (IOException e) {
                if (attempt == 2) {
                    log.warn("change push failed after 3 attempts (" + events.size()
                        + " events); subscribers will catch up via get_changes: " + e.getMessage());
                    return;
                }
                try {
                    Thread.sleep(200L * (attempt + 1));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    /**
     * HTTP POST request
     */
    private void post(String path, JsonObject body) throws IOException {
        URL url = new URL(daemonUrl + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        if (WORKER_SECRET != null) conn.setRequestProperty("X-Worker-Secret", WORKER_SECRET);
        conn.setDoOutput(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        byte[] bodyBytes = gson.toJson(body).getBytes(StandardCharsets.UTF_8);
        conn.setRequestProperty("Content-Length", String.valueOf(bodyBytes.length));

        try (OutputStream os = conn.getOutputStream()) {
            os.write(bodyBytes);
        }

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            throw new IOException("HTTP POST failed: " + responseCode);
        }

        // Read and discard response
        try (InputStream is = conn.getInputStream()) {
            is.readAllBytes();
        }
    }
}
