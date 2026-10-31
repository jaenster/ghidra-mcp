package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import com.ghidramcp.operations.ProjectOps;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Keeps a read-only server session on the latest version of its program.
 *
 * A read-only open fixes the program at the version that was current when it was opened,
 * and holds no checkout. This polls the repository for the program's current version and,
 * when a newer one is checked in, opens that version read-only next to the old one, swaps
 * it in while no command runs, and only then releases the old copy - so calls in flight
 * finish on the version they started on and calls that arrive meanwhile just wait.
 * A failed reload keeps the old version and is retried on the next poll.
 */
public final class VersionFollower {
    private final GhidraEngine engine;
    private final ProgramReloader reloader;
    private final String programPath;
    private final long intervalMs;
    private final Logger log;
    private final ScheduledExecutorService timer;

    public VersionFollower(GhidraEngine engine, ProgramReloader reloader, String programPath,
                           long intervalMs, Logger log) {
        this.engine = engine;
        this.reloader = reloader;
        this.programPath = programPath;
        this.intervalMs = intervalMs;
        this.log = log;
        this.timer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "version-follower");
            t.setDaemon(true);
            return t;
        });
    }

    public void start() {
        log.info("Following the latest server version of " + programPath + " every " + intervalMs + " ms");
        timer.scheduleWithFixedDelay(this::pollSafely, intervalMs, intervalMs, TimeUnit.MILLISECONDS);
    }

    public void stop() {
        timer.shutdownNow();
    }

    private void pollSafely() {
        try {
            poll();
        } catch (Throwable t) {
            log.warn("Version check failed, still serving version "
                    + engine.getContext().getServedVersion() + ": " + t.getMessage());
        }
    }

    /** One check; package-visible so a test could drive it without the timer. */
    void poll() throws Exception {
        GhidraContext ctx = engine.getContext();
        ProjectOps ops = engine.projectOps();
        int latest = ops.serverVersionOf(programPath);
        ctx.setServerLatestVersion(latest);
        Integer served = ctx.getServedVersion();
        if (served != null && latest <= served) {
            return;
        }

        log.info("Version " + latest + " of " + programPath + " is on the server (serving "
                + served + "); loading it");
        long started = System.currentTimeMillis();
        reloader.reload(programPath, latest, true);
        log.info("Now serving version " + latest + " of " + programPath + " (loaded in "
                + (System.currentTimeMillis() - started) + " ms)");
    }
}
