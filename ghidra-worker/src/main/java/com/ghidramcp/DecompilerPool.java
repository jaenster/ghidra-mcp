package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe pool of DecompInterface instances for parallel decompilation.
 *
 * Each DecompInterface.decompileFunction() is synchronized internally,
 * so N instances are needed for N-way parallelism.
 */
public class DecompilerPool {
    private static final int DEFAULT_POOL_SIZE =
            Integer.getInteger("ghidra.mcp.decompiler.threads", 4);

    private final BlockingQueue<DecompInterface> available;
    private final ExecutorService executor;
    private final List<DecompInterface> allInstances;
    private final int poolSize;
    private final Logger log;
    private final Program program;
    /** Last program modification number seen by each pooled DecompInterface instance. */
    private final Map<DecompInterface, Long> lastModNumber;
    private volatile boolean shutdown = false;

    /**
     * Bodies decompiled once and still owed to a later caller.
     *
     * list_functions has to decompile every function with an undefined parameter or local
     * to report its resolved type, and the bulk extractor then asks batch_decompile for the
     * body of that same function - two full decompiles of the same code, and the first one
     * threw its C text away. Keeping that text here makes the second decompile a map lookup.
     *
     * Entries are handed out once and removed, so the batch pass drains what the list pass
     * filled. Keyed by entry-point address; invalidated wholesale when the program changes.
     */
    private final Map<String, String> bodyCache = new LinkedHashMap<>();
    private final AtomicLong bodyCacheMod = new AtomicLong(Long.MIN_VALUE);
    private long bodyCacheChars = 0;

    /**
     * Cap on the characters held in bodyCache. The whole 1.14d Game.exe corpus is ~40M
     * characters, so the default holds all of it; the cap is there so a client that lists
     * without ever decompiling cannot grow the worker heap without bound.
     */
    private static final long BODY_CACHE_MAX_CHARS = bodyCacheBudget();

    private static long bodyCacheBudget() {
        String mb = System.getenv("GHIDRA_MCP_DECOMPILE_CACHE_MB");
        long megabytes = 256;
        if (mb != null) {
            try {
                megabytes = Math.max(0, Long.parseLong(mb.trim()));
            } catch (NumberFormatException e) {
                // keep the default
            }
        }
        return megabytes * 1024L * 1024L;
    }

    public DecompilerPool(Program program, int poolSize, Logger log) {
        this.poolSize = poolSize;
        this.log = log;
        this.program = program;
        this.available = new ArrayBlockingQueue<>(poolSize);
        this.allInstances = new ArrayList<>(poolSize);
        this.lastModNumber = new IdentityHashMap<>(poolSize);
        this.executor = Executors.newFixedThreadPool(poolSize, r -> {
            Thread t = new Thread(r, "decompiler-pool");
            t.setDaemon(true);
            return t;
        });

        long initialMod = program.getModificationNumber();
        for (int i = 0; i < poolSize; i++) {
            DecompInterface decomp = createDecompiler(program);
            allInstances.add(decomp);
            lastModNumber.put(decomp, initialMod);
            available.add(decomp);
        }

        log.info("DecompilerPool created with " + poolSize + " instances");
    }

    public DecompilerPool(Program program, Logger log) {
        this(program, DEFAULT_POOL_SIZE, log);
    }

    public int getPoolSize() {
        return poolSize;
    }

    /**
     * Submit a decompilation task to the pool.
     */
    public Future<DecompileResults> submit(Function func, int timeout) {
        if (shutdown) {
            throw new RejectedExecutionException("DecompilerPool is shut down");
        }
        return executor.submit(() -> {
            DecompInterface decomp = borrow();
            try {
                return decomp.decompileFunction(func, timeout, new ConsoleTaskMonitor());
            } finally {
                returnInstance(decomp);
            }
        });
    }

    /**
     * Decompile synchronously using a pooled instance.
     */
    public DecompileResults decompile(Function func, int timeout) throws Exception {
        return submit(func, timeout).get();
    }

    private DecompInterface borrow() throws InterruptedException {
        DecompInterface decomp = available.take();
        long currentMod = program.getModificationNumber();
        Long seen = lastModNumber.get(decomp);
        if (seen == null || seen != currentMod) {
            decomp.flushCache();
            lastModNumber.put(decomp, currentMod);
        }
        return decomp;
    }

    /**
     * Remember the C text of a completed decompile so a later caller can skip the work.
     * No-op for a failed decompile: leaving it uncached keeps the failure path - warnings
     * and all - exactly as it was.
     */
    public void cacheBody(Function func, DecompileResults results) {
        if (results == null || !results.decompileCompleted()) return;
        ghidra.app.decompiler.DecompiledFunction df = results.getDecompiledFunction();
        String c = df != null ? df.getC() : null;
        if (c == null) return;
        synchronized (bodyCache) {
            checkModLocked();
            if (bodyCacheChars + c.length() > BODY_CACHE_MAX_CHARS) return;
            String prev = bodyCache.put(func.getEntryPoint().toString(), c);
            if (prev != null) bodyCacheChars -= prev.length();
            bodyCacheChars += c.length();
        }
    }

    /** Take a cached body, removing it, or null when there is none. */
    public String takeCachedBody(Function func) {
        synchronized (bodyCache) {
            checkModLocked();
            String c = bodyCache.remove(func.getEntryPoint().toString());
            if (c != null) bodyCacheChars -= c.length();
            return c;
        }
    }

    /** Drop everything cached under an older revision of the program. */
    private void checkModLocked() {
        long current = program.getModificationNumber();
        if (bodyCacheMod.get() != current) {
            bodyCache.clear();
            bodyCacheChars = 0;
            bodyCacheMod.set(current);
        }
    }

    private void returnInstance(DecompInterface decomp) {
        if (!shutdown) {
            available.offer(decomp);
        }
    }

    public void shutdown() {
        shutdown = true;
        executor.shutdownNow();
        for (DecompInterface decomp : allInstances) {
            try {
                decomp.dispose();
            } catch (Exception e) {
                // ignore during shutdown
            }
        }
        allInstances.clear();
        available.clear();
        synchronized (bodyCache) {
            bodyCache.clear();
            bodyCacheChars = 0;
        }
        log.info("DecompilerPool shut down");
    }

    /**
     * Create and configure a DecompInterface with standard options.
     */
    public static DecompInterface createDecompiler(Program program) {
        DecompInterface decompiler = new DecompInterface();
        configureDecompileOptions(decompiler);
        decompiler.openProgram(program);
        return decompiler;
    }

    /**
     * Apply standard decompile options. Shared with ProjectOps single-decompiler creation.
     */
    static void configureDecompileOptions(DecompInterface decompiler) {
        DecompileOptions options = new DecompileOptions();
        options.setConventionPrint(true);
        options.setNoCastPrint(false);
        options.setPRECommentIncluded(true);
        options.setPLATECommentIncluded(true);
        options.setPOSTCommentIncluded(true);
        options.setEOLCommentIncluded(true);
        options.setWARNCommentIncluded(true);
        options.setHeadCommentIncluded(true);
        options.setEliminateUnreachable(false);

        try {
            java.lang.reflect.Field nsField = DecompileOptions.class.getDeclaredField("namespaceStrategy");
            nsField.setAccessible(true);
            nsField.set(options, DecompileOptions.NamespaceStrategy.All);
        } catch (Exception e) {
            // Ignore — field may not exist in all Ghidra versions
        }

        decompiler.setOptions(options);
    }
}
