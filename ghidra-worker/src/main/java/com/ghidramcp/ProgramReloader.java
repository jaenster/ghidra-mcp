package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import com.ghidramcp.operations.ProjectOps;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;

import java.util.function.Supplier;

/**
 * Swaps a read-only server program for a freshly opened copy of one version of it.
 *
 * The new copy is opened outside the dispatcher fence - that is the slow part, and
 * commands keep running on the old copy meanwhile - then swapped in while no command
 * runs, and only then is the old copy released. Used both to follow newer versions and
 * to replace a copy whose server connection died.
 */
public final class ProgramReloader {
    private final GhidraEngine engine;
    /** The dispatcher is replaced when the worker reconnects to the daemon; always fence on the current one. */
    private final Supplier<CommandDispatcher> dispatcher;
    private final Logger log;

    public ProgramReloader(GhidraEngine engine, Supplier<CommandDispatcher> dispatcher, Logger log) {
        this.engine = engine;
        this.dispatcher = dispatcher;
        this.log = log;
    }

    /**
     * Open {@code version} of {@code programPath} read-only and swap it in. When
     * {@code served} is true the context records it as the version being served.
     * Synchronized so a version follow and a connection recovery never load at once.
     */
    public synchronized void reload(String programPath, int version, boolean served) throws Exception {
        GhidraContext ctx = engine.getContext();
        ProjectOps ops = engine.projectOps();
        Program next = ops.openReadOnlyVersion(programPath, version);
        DecompInterface decomp;
        try {
            decomp = ops.newDecompiler(next);
        } catch (RuntimeException e) {
            next.release(ctx);
            throw e;
        }
        FlatProgramAPI api = new FlatProgramAPI(next);

        GhidraContext.Replaced[] replaced = new GhidraContext.Replaced[1];
        dispatcher.get().runExclusive(() -> {
            replaced[0] = ctx.replaceProgram(programPath, next, api, decomp);
            if (served) {
                ctx.setServedVersion(version, System.currentTimeMillis());
            }
        });
        release(replaced[0]);
    }

    private void release(GhidraContext.Replaced old) {
        GhidraContext ctx = engine.getContext();
        if (old == null) {
            return;
        }
        if (old.pool != null) {
            old.pool.shutdown();
        }
        if (old.tracker != null) {
            try {
                old.tracker.detach();
            } catch (Exception e) {
                log.warn("Detaching the old dirty tracker failed: " + e.getMessage());
            }
        }
        if (old.decompiler != null) {
            try {
                old.decompiler.dispose();
            } catch (Exception e) {
                log.warn("Disposing the old decompiler failed: " + e.getMessage());
            }
        }
        if (old.program != null && !old.program.isClosed()) {
            try {
                old.program.release(ctx);
            } catch (Exception e) {
                // A copy whose server connection died may fail to close cleanly; it is
                // unreachable from the context already, so this only logs.
                log.warn("Releasing the old program failed: " + e.getMessage());
            }
        }
    }
}
