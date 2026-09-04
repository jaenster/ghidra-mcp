package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Dispatches commands with a ReadWriteLock fence.
 *
 * Read commands (decompile, list, get, search, etc.) execute in parallel on
 * a thread pool under the read lock.
 *
 * Write commands (rename, set_*, create_*, delete_*, undo, redo, etc.) acquire
 * the write lock, which drains all in-flight reads first, then execute on the
 * caller thread.
 *
 * This ensures that writes never run concurrently with reads, and reads never
 * run concurrently with writes, matching Ghidra's Program DB threading model.
 */
public class CommandDispatcher {
    private static final int READ_POOL_SIZE =
            Integer.getInteger("ghidra.mcp.read.threads", 4);
    private static final Gson gson = new Gson();

    private final ReentrantReadWriteLock fence = new ReentrantReadWriteLock();
    private final ExecutorService readPool;
    private final CommandHandler handler;
    private final Logger log;

    // Track which thread is running which command (for heartbeat/dashboard)
    private final ConcurrentHashMap<String, String> activeThreadCommands = new ConcurrentHashMap<>();

    /**
     * Commands that only read from the Program DB and can run in parallel.
     */
    private static final Set<String> READ_COMMANDS = Set.of(
        "decompile", "batch_decompile", "batch_pcode",
        "list_repos", "list_functions", "list_programs", "list_strings", "list_segments",
        "import_status", "analyze_status",
        "list_imports", "list_exports", "list_namespaces", "list_symbols",
        "list_data_types", "list_comments", "list_bookmarks", "list_equates",
        "get_program_info", "get_function_info", "get_function_summary",
        "get_xrefs", "get_xrefs_with_context", "get_call_graph",
        "get_class_info", "get_pcode", "get_data_type", "get_basic_blocks",
        "get_analysis_hints", "get_disassembly", "get_stack_frame",
        "get_switch_table", "get_undo_history", "get_line_mappings",
        "get_global_variables", "get_data_at_address", "get_symbol_after",
        "get_hexdump", "get_cache_version", "get_dirty_symbols", "get_changes",
        "read_memory", "read_data_value",
        "find_call_path", "find_functions_matching",
        "search", "trace_data_flow", "detect_table",
        "export_all_c", "export_type_archive",
        "vt_list_matches", "vt_get_correlators"
    );

    /**
     * Commands that stay answerable while auto-analysis is rewriting the program: they
     * read a job record, never the Program DB.
     */
    private static final Set<String> ANALYSIS_SAFE_COMMANDS = Set.of(
        "analyze_status", "import_status", "get_changes"
    );

    public CommandDispatcher(CommandHandler handler, Logger log) {
        this.handler = handler;
        this.log = log;
        AtomicInteger threadIdx = new AtomicInteger(0);
        this.readPool = Executors.newFixedThreadPool(READ_POOL_SIZE, r -> {
            Thread t = new Thread(r, "cmd-read-pool-" + threadIdx.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Dispatch a command. Returns a Future that completes with the result.
     * Read commands run on the pool; write commands run on the caller's thread.
     */
    public Future<JsonObject> dispatch(String commandType, JsonObject params) {
        // Auto-analysis runs on its own thread, outside this fence, and rewrites the whole
        // program. Nothing else may touch the Program DB until it is done.
        String analysisJob = handler.engine().autoAnalysis().runningJobId();
        if (analysisJob != null && !ANALYSIS_SAFE_COMMANDS.contains(commandType)) {
            CompletableFuture<JsonObject> rejected = new CompletableFuture<>();
            rejected.completeExceptionally(new IllegalStateException(
                "Auto-analysis in progress (job " + analysisJob + "); the program is being "
                + "rewritten. Poll analyze_status until it reports finished."));
            return rejected;
        }

        if (READ_COMMANDS.contains(commandType)) {
            return readPool.submit(() -> {
                fence.readLock().lock();
                String thread = Thread.currentThread().getName();
                activeThreadCommands.put(thread, commandType);
                long start = System.currentTimeMillis();
                log.info("CMD START [" + thread + "] " + commandType + " " + truncateParams(params));
                try {
                    JsonObject result = handler.handle(commandType, params);
                    long elapsed = System.currentTimeMillis() - start;
                    String resultJson = gson.toJson(result);
                    log.info("CMD DONE  [" + thread + "] " + commandType + " " + elapsed + "ms result=" + resultJson.length() + "ch");
                    return result;
                } catch (Exception e) {
                    long elapsed = System.currentTimeMillis() - start;
                    log.error("CMD ERROR [" + thread + "] " + commandType + " " + elapsed + "ms: " + e.getMessage());
                    throw e;
                } finally {
                    activeThreadCommands.remove(thread);
                    fence.readLock().unlock();
                }
            });
        } else {
            // Write command — execute synchronously under write lock
            CompletableFuture<JsonObject> future = new CompletableFuture<>();
            fence.writeLock().lock();
            String thread = Thread.currentThread().getName();
            activeThreadCommands.put(thread, commandType);
            long start = System.currentTimeMillis();
            log.info("CMD START [" + thread + "] " + commandType + " (write) " + truncateParams(params));
            try {
                JsonObject result = handler.handle(commandType, params);
                // Ghidra delivers change records on a 500 ms timer, not when the
                // transaction ends, so a write that simply returns leaves its own change
                // invisible for up to half a second. That timing - not a gap in what the
                // listeners watch - is why struct-field and variable retypes used to look
                // like they produced no event. Flush here, while the write lock is still
                // held, and stamp the reply with the resulting sequence so a caller can
                // wait for exactly its own change instead of guessing.
                flushChangeEvents();
                stampChangeSeq(result);
                long elapsed = System.currentTimeMillis() - start;
                String resultJson = gson.toJson(result);
                log.info("CMD DONE  [" + thread + "] " + commandType + " (write) " + elapsed + "ms result=" + resultJson.length() + "ch");
                future.complete(result);
            } catch (Exception e) {
                long elapsed = System.currentTimeMillis() - start;
                log.error("CMD ERROR [" + thread + "] " + commandType + " (write) " + elapsed + "ms: " + e.getMessage());
                future.completeExceptionally(e);
            } finally {
                activeThreadCommands.remove(thread);
                fence.writeLock().unlock();
            }
            return future;
        }
    }

    /** Force Ghidra to deliver any pending change records now. Best effort. */
    private void flushChangeEvents() {
        try {
            var program = handler.engine().getProgram();
            if (program != null) {
                program.flushEvents();
            }
        } catch (Exception e) {
            log.warn("flushEvents failed: " + e.getMessage());
        }
    }

    /**
     * Record the journal position a write reached, so a caller knows the sequence at
     * which its own change is readable. Without it a consumer polling get_changes cannot
     * tell "not yet delivered" from "nothing happened".
     */
    private void stampChangeSeq(JsonObject result) {
        try {
            ChangeJournal journal = handler.engine().getContext().getChangeJournal();
            if (journal != null && result != null) {
                result.addProperty("changeSeq", journal.head());
            }
        } catch (Exception e) {
            log.warn("changeSeq stamp failed: " + e.getMessage());
        }
    }

    /**
     * Get thread status for heartbeat/dashboard.
     */
    public Map<String, String> getActiveThreadCommands() {
        return Map.copyOf(activeThreadCommands);
    }

    public int getReadPoolSize() {
        return READ_POOL_SIZE;
    }

    public void shutdown() {
        readPool.shutdownNow();
    }

    private static String truncateParams(JsonObject params) {
        if (params == null || params.size() == 0) return "{}";
        String s = params.toString();
        if (s.length() <= 200) return s;
        return s.substring(0, 200) + "...(" + s.length() + "ch)";
    }
}
