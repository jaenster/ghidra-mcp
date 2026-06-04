package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import com.google.gson.JsonArray;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Main entry point for the Ghidra MCP worker process.
 *
 * This worker:
 * 1. Initializes Ghidra in headless mode
 * 2. Loads a binary file for analysis
 * 3. Connects back to the Node.js daemon
 * 4. Processes commands and returns results
 */
public class Worker {
    private static final Gson gson = new Gson();

    private final String workerId;
    private final String sessionId;
    private final String daemonUrl;
    private final String binaryPath;
    private final String projectPath;
    private final String programPath;  // path within .gpr project (null = auto-select)
    private final boolean autoAnalyze;
    private final int analysisTimeout;
    private final boolean readOnly;

    private GhidraEngine engine;
    private DaemonClient client;
    private Logger log;
    private final AtomicBoolean running = new AtomicBoolean(true);

    public Worker(String workerId, String sessionId, String daemonUrl,
                  String binaryPath, String projectPath, String programPath,
                  boolean autoAnalyze, int analysisTimeout, boolean readOnly) {
        this.workerId = workerId;
        this.sessionId = sessionId;
        this.daemonUrl = daemonUrl;
        this.binaryPath = binaryPath;
        this.projectPath = projectPath;
        this.programPath = programPath;
        this.autoAnalyze = autoAnalyze;
        this.analysisTimeout = analysisTimeout;
        this.readOnly = readOnly;
    }

    public void run() throws Exception {
        // Initialize WebSocket logging first
        Logger.initWebSocket(daemonUrl, workerId, sessionId);
        log = Logger.create("Worker", workerId, sessionId);

        log.info("Starting Ghidra MCP Worker");
        log.info("Worker ID: " + workerId);
        log.info("Session ID: " + sessionId);
        log.info("Binary: " + binaryPath);
        log.info("Project: " + projectPath);
        log.info("Auto-analyze: " + autoAnalyze);

        // Initialize daemon client
        client = new DaemonClient(daemonUrl, workerId, sessionId, log.child("DaemonClient"));

        // Verify daemon is reachable before heavy initialization
        client.checkConnection();

        try {
            // Initialize Ghidra
            log.info("Initializing Ghidra...");
            engine = new GhidraEngine(projectPath, log.child("GhidraEngine"));

            // Check if this is a .gpr project file or a binary
            File inputFile = new File(binaryPath);
            if (binaryPath.endsWith(".gpr")) {
                // Open existing Ghidra project
                if (readOnly) {
                    log.info("Opening project read-only: " + binaryPath);
                    engine.openProjectReadOnly(inputFile, programPath);
                    log.info("Project opened read-only successfully");
                } else {
                    log.info("Opening project: " + binaryPath);
                    engine.openProject(inputFile, programPath);
                    log.info("Project opened successfully");
                }
            } else {
                // Import binary into new project
                log.info("Loading binary: " + binaryPath);
                engine.loadProgram(inputFile, autoAnalyze, analysisTimeout);
                log.info("Binary loaded successfully");
            }

            // Register with daemon
            client.register();
            log.info("Registered with daemon");

            // Start background heartbeat so long-running commands don't cause staleness
            client.startHeartbeatThread();

            // Main command loop with parallel dispatch
            final AtomicReference<CommandDispatcher> dispatcherRef = new AtomicReference<>();
            CommandHandler handler = new CommandHandler(engine, log.child("CommandHandler"));
            CommandDispatcher dispatcher = new CommandDispatcher(handler, log.child("Dispatcher"));
            dispatcherRef.set(dispatcher);

            // Wire thread status into heartbeat payload
            client.setHeartbeatExtraSupplier(() -> {
                CommandDispatcher d = dispatcherRef.get();
                JsonObject threads = new JsonObject();
                threads.addProperty("readPoolSize", d.getReadPoolSize());
                Map<String, String> active = d.getActiveThreadCommands();
                threads.addProperty("readPoolActive", active.size());
                JsonArray activeThreads = new JsonArray();
                JsonObject currentCommands = new JsonObject();
                for (var entry : active.entrySet()) {
                    activeThreads.add(entry.getKey());
                    currentCommands.addProperty(entry.getKey(), entry.getValue());
                }
                threads.add("activeThreads", activeThreads);
                threads.add("currentCommands", currentCommands);
                JsonObject extra = new JsonObject();
                extra.add("threads", threads);
                return extra;
            });

            while (running.get()) {
                try {
                    // Poll for commands
                    JsonObject command = client.pollCommand();

                    if (command != null) {
                        String commandId = command.get("id").getAsString();
                        String commandType = command.get("command").getAsString();
                        JsonObject params = command.has("params")
                            ? command.getAsJsonObject("params")
                            : new JsonObject();

                        log.info("Processing command: " + commandType, Map.of(
                            "thread", Thread.currentThread().getName(),
                            "commandId", commandId));

                        // Handle shutdown command
                        if ("shutdown".equals(commandType)) {
                            dispatcher.shutdown();
                            boolean save = params.has("save") && params.get("save").getAsBoolean();
                            engine.close(save);

                            JsonObject result = new JsonObject();
                            result.addProperty("success", true);
                            client.sendResult(commandId, true, result, null);

                            running.set(false);
                            break;
                        }

                        // Dispatch command (reads run in parallel, writes are exclusive)
                        long cmdStart = System.currentTimeMillis();
                        try {
                            client.setHeartbeatStatus("busy");
                            Future<JsonObject> future = dispatcher.dispatch(commandType, params);
                            JsonObject result = future.get();
                            client.sendResult(commandId, true, result, null);
                            long elapsed = System.currentTimeMillis() - cmdStart;
                            log.info("Result posted: " + commandType + " ok " + elapsed + "ms", Map.of(
                                "commandId", commandId));
                        } catch (java.util.concurrent.ExecutionException e) {
                            Throwable cause = e.getCause() != null ? e.getCause() : e;
                            long elapsed = System.currentTimeMillis() - cmdStart;
                            log.error("Command error: " + cause.getMessage() + " " + elapsed + "ms", Map.of("command", commandType));
                            cause.printStackTrace();
                            client.sendResult(commandId, false, null, cause.getMessage());
                        } catch (Exception e) {
                            long elapsed = System.currentTimeMillis() - cmdStart;
                            log.error("Command error: " + e.getMessage() + " " + elapsed + "ms", Map.of("command", commandType));
                            e.printStackTrace();
                            client.sendResult(commandId, false, null, e.getMessage());
                        } finally {
                            client.setHeartbeatStatus("idle");
                        }
                    }

                } catch (Exception e) {
                    if (isConnectionError(e)) {
                        log.warn("Lost connection to daemon, entering reconnection mode");

                        // Save project immediately
                        try {
                            engine.save();
                            log.info("Project saved before reconnection");
                        } catch (Exception saveErr) {
                            log.error("Failed to save before reconnection: " + saveErr.getMessage());
                        }

                        // Reconnection loop: retry every 1s for 3 minutes
                        boolean reconnected = false;
                        long reconnectStart = System.currentTimeMillis();
                        long reconnectTimeout = 180_000; // 3 minutes

                        while (running.get() && !reconnected &&
                               (System.currentTimeMillis() - reconnectStart) < reconnectTimeout) {
                            Thread.sleep(1000);

                            if (client.isDaemonReachable()) {
                                try {
                                    String newWorkerId = client.reconnectRegister(
                                        binaryPath, projectPath, readOnly);
                                    log.info("Reconnected with new workerId: " + newWorkerId);

                                    // Re-init WebSocket logging with new identity
                                    Logger.shutdown();
                                    Logger.initWebSocket(daemonUrl, newWorkerId, sessionId);
                                    log = Logger.create("Worker", newWorkerId, sessionId);

                                    // Re-register the command handler's and dispatcher's logger
                                    handler = new CommandHandler(engine, log.child("CommandHandler"));
                                    dispatcher = new CommandDispatcher(handler, log.child("Dispatcher"));
                                    dispatcherRef.set(dispatcher);

                                    reconnected = true;
                                    log.info("Reconnection complete, resuming command loop");
                                } catch (Exception reconnErr) {
                                    log.warn("Reconnect attempt failed: " + reconnErr.getMessage());
                                }
                            }
                        }

                        if (!reconnected) {
                            log.error("Failed to reconnect after " + reconnectTimeout/1000 + "s, shutting down");
                            running.set(false);
                        }
                    } else {
                        log.error("Error in command loop: " + e.getMessage());
                        e.printStackTrace();
                        Thread.sleep(1000);
                    }
                }
            }

        } catch (Exception e) {
            log.error("Fatal error: " + e.getMessage());
            e.printStackTrace();
            throw e;
        } finally {
            log.info("Shutting down...");
            client.stopHeartbeatThread();
            if (engine != null) {
                engine.close(true);
            }
            Logger.shutdown();
        }
    }

    /**
     * Check if an exception indicates a lost connection to the daemon
     */
    private static boolean isConnectionError(Exception e) {
        Throwable t = e;
        while (t != null) {
            if (t instanceof java.net.ConnectException ||
                t instanceof java.net.SocketException ||
                t instanceof java.io.EOFException) {
                return true;
            }
            String msg = t.getMessage();
            if (msg != null && (msg.contains("Connection refused") ||
                                msg.contains("Connection reset"))) {
                return true;
            }
            t = t.getCause();
        }
        return false;
    }

    public static void main(String[] args) {
        // Catch uncaught exceptions from ANY thread (Jython, Ghidra internals, GC finalizers)
        // so that native errors (OutOfMemoryError, NoClassDefFoundError) produce stderr output
        // before the JVM exits, allowing the daemon to detect and report the crash.
        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) -> {
            System.err.println("[FATAL] Uncaught exception in thread " + thread.getName());
            throwable.printStackTrace(System.err);
            System.err.flush();
            System.exit(1);
        });

        // Parse command-line arguments
        String workerId = null;
        String sessionId = null;
        String daemonUrl = null;
        String binaryPath = null;
        String projectPath = null;
        String programPath = null;
        boolean autoAnalyze = true;
        int analysisTimeout = 300000;
        boolean readOnly = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--worker-id":
                    workerId = args[++i];
                    break;
                case "--session-id":
                    sessionId = args[++i];
                    break;
                case "--daemon-url":
                    daemonUrl = args[++i];
                    break;
                case "--binary":
                    binaryPath = args[++i];
                    break;
                case "--project":
                    projectPath = args[++i];
                    break;
                case "--program-path":
                    programPath = args[++i];
                    break;
                case "--analyze":
                    autoAnalyze = true;
                    break;
                case "--no-analyze":
                    autoAnalyze = false;
                    break;
                case "--analysis-timeout":
                    analysisTimeout = Integer.parseInt(args[++i]);
                    break;
                case "--read-only":
                    readOnly = true;
                    break;
            }
        }

        // Validate required arguments
        if (workerId == null || sessionId == null || daemonUrl == null ||
            binaryPath == null || projectPath == null) {
            System.err.println("Usage: Worker --worker-id <id> --session-id <id> --daemon-url <url> " +
                             "--binary <path> --project <path> [--analyze] [--analysis-timeout <ms>]");
            System.exit(1);
        }

        try {
            Worker worker = new Worker(workerId, sessionId, daemonUrl,
                                       binaryPath, projectPath, programPath,
                                       autoAnalyze, analysisTimeout, readOnly);
            worker.run();
        } catch (Exception e) {
            System.err.println("[Worker] Fatal error: " + e.getMessage());
            e.printStackTrace();
            Logger.shutdown();
            System.exit(1);
        }
    }
}
