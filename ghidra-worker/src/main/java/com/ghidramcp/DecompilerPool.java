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
import java.util.List;
import java.util.concurrent.*;

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
    private volatile boolean shutdown = false;

    public DecompilerPool(Program program, int poolSize, Logger log) {
        this.poolSize = poolSize;
        this.log = log;
        this.available = new ArrayBlockingQueue<>(poolSize);
        this.allInstances = new ArrayList<>(poolSize);
        this.executor = Executors.newFixedThreadPool(poolSize, r -> {
            Thread t = new Thread(r, "decompiler-pool");
            t.setDaemon(true);
            return t;
        });

        for (int i = 0; i < poolSize; i++) {
            DecompInterface decomp = createDecompiler(program);
            allInstances.add(decomp);
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
        return available.take();
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
