package com.ghidramcp;

import com.ghidramcp.ServerConnection.ServerUnavailableException;
import com.ghidramcp.logging.Logger;
import com.google.gson.JsonObject;

import ghidra.framework.client.RemoteAdapterListener;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Brings a worker back after its Ghidra Server connection died, typically because the
 * server restarted and forgot every RMI object the worker held stubs for.
 *
 * Recovery reconnects the server and repository adapters, which is all a writable
 * session needs: its checkout is a local copy and the server keeps the checkout record
 * across a restart, so a check-in works again once the repository is reconnected. A
 * read-only session also has to reopen its programs, because a read-only copy pages
 * from a buffer file on the server and that remote handle is dead for good.
 *
 * Commands that fail with a connection loss call {@link #recover}; a watchdog probes the
 * server on a timer too, so a quiet worker recovers before anyone asks it something, and
 * its last result rides the heartbeat so the daemon can replace a worker that cannot
 * recover.
 */
public final class ServerRecovery {
    private final GhidraEngine engine;
    private final ProgramReloader reloader;
    /** The program whose version the context reports as served, or null. */
    private final String servedPath;
    private final Logger log;
    private final ScheduledExecutorService timer;
    /** Held strongly: Ghidra keeps adapter listeners in a weak set. */
    private final RemoteAdapterListener disconnectListener;

    /** Bumped by every successful recovery; a command compares it to skip a recovery another thread already did. */
    private volatile long generation = 0;
    /** Set when the server adapter reported a disconnect: read-only copies opened before it are dead. */
    private volatile boolean programsStale = false;

    private volatile boolean healthy = true;
    private volatile String lastError = null;
    private volatile long unhealthySince = 0;
    private volatile long lastProbeAt = 0;
    private volatile long lastRecoveredAt = 0;

    public ServerRecovery(GhidraEngine engine, ProgramReloader reloader, String servedPath, Logger log) {
        this.engine = engine;
        this.reloader = reloader;
        this.servedPath = servedPath;
        this.log = log;
        this.timer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "server-watchdog");
            t.setDaemon(true);
            return t;
        });
        this.disconnectListener = adapter -> {
            if (adapter instanceof RepositoryServerAdapter s && !s.isConnected()) {
                if (!programsStale) {
                    log.warn("Ghidra Server connection lost");
                }
                programsStale = true;
            }
        };
        RepositoryServerAdapter server = engine.getContext().getServerAdapter();
        if (server != null) {
            server.addListener(disconnectListener);
        }
    }

    public long generation() {
        return generation;
    }

    public void start(long intervalMs) {
        log.info("Probing the Ghidra Server connection every " + intervalMs + " ms");
        timer.scheduleWithFixedDelay(this::probeSafely, intervalMs, intervalMs, TimeUnit.MILLISECONDS);
    }

    public void stop() {
        timer.shutdownNow();
    }

    /**
     * Restore the connection after a command failed with {@code cause}. If another thread
     * already recovered since {@code seenGeneration} was read, this returns at once.
     */
    public synchronized void recover(long seenGeneration, Throwable cause) throws ServerUnavailableException {
        if (generation != seenGeneration) {
            return;
        }
        log.warn("Ghidra Server connection lost (" + ServerConnection.describe(cause) + "); reconnecting");
        restore();
    }

    /** One watchdog round: a cheap server call, and a full recovery if it fails or copies went stale. */
    void probe() {
        lastProbeAt = System.currentTimeMillis();
        long seen = generation;
        try {
            touchServer();
            if (!programsStale || !engine.isReadOnly()) {
                programsStale = false;
                markHealthy();
                return;
            }
        } catch (Exception e) {
            log.warn("Ghidra Server probe failed: " + ServerConnection.describe(e));
        }
        synchronized (this) {
            if (generation != seen) {
                return;
            }
            try {
                restore();
            } catch (ServerUnavailableException e) {
                // restore() recorded it; the next probe tries again.
            }
        }
    }

    private void probeSafely() {
        try {
            probe();
        } catch (Throwable t) {
            log.warn("Ghidra Server watchdog failed: " + t);
        }
    }

    /** Reconnect, reopen read-only programs, and verify. Caller holds this monitor. */
    private void restore() throws ServerUnavailableException {
        long started = System.currentTimeMillis();
        try {
            reconnect();
            if (engine.isReadOnly()) {
                reopenReadOnlyPrograms();
            }
            programsStale = false;
            generation++;
            lastRecoveredAt = System.currentTimeMillis();
            markHealthy();
            log.info("Ghidra Server connection restored in " + (System.currentTimeMillis() - started) + " ms");
        } catch (Exception e) {
            String detail = ServerConnection.describe(e);
            markUnhealthy(detail);
            log.error("Ghidra Server connection could not be restored: " + detail);
            throw new ServerUnavailableException(
                    "the connection to the Ghidra Server was lost and could not be restored (" + detail
                            + "). The server may be restarting; retry shortly.", e);
        }
    }

    /**
     * Re-establish the server and repository connections. Ghidra's adapters reconnect
     * from scratch once they have noticed the loss, but the first call after a restart
     * only notices it (and throws), so this tries twice.
     */
    private void reconnect() throws Exception {
        Exception last = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            try {
                touchServer();
                return;
            } catch (Exception e) {
                last = e;
            }
        }
        throw last;
    }

    /** A call that must reach the live server; reconnects adapters that already know they are down. */
    private void touchServer() throws Exception {
        GhidraContext ctx = engine.getContext();
        Project project = ctx.getServerProject();
        RepositoryAdapter repo = project != null ? project.getRepository() : null;
        if (repo != null) {
            // connect() tests a live handle with a remote call and rebuilds a dead one,
            // reconnecting the server adapter first when that went down too.
            repo.connect();
            if (!repo.isConnected()) {
                throw new java.io.IOException("Repository " + repo.getName() + " is not connected");
            }
            // The repository handle answering does not prove the server handle is alive.
            repo.getServer().connect();
            return;
        }
        RepositoryServerAdapter server = ctx.getServerAdapter();
        if (server == null) {
            return;
        }
        if (!server.connect()) {
            throw new java.io.IOException("Ghidra Server connect was cancelled");
        }
    }

    private void reopenReadOnlyPrograms() throws Exception {
        GhidraContext ctx = engine.getContext();
        List<String> paths = new ArrayList<>(ctx.getPrograms().keySet());
        for (String path : paths) {
            DomainFile df = ctx.getProjectData().getFile(path);
            if (df == null) {
                throw new java.io.IOException("Program is no longer in the repository: " + path);
            }
            int version = df.isVersioned()
                    ? engine.projectOps().serverVersionOf(path)
                    : DomainFile.DEFAULT_VERSION;
            log.info("Reopening " + path + " at version " + version);
            reloader.reload(path, version, path.equals(servedPath) && version != DomainFile.DEFAULT_VERSION);
        }
    }

    private void markHealthy() {
        if (!healthy) {
            log.info("Ghidra Server connection healthy again");
        }
        healthy = true;
        lastError = null;
        unhealthySince = 0;
    }

    private void markUnhealthy(String detail) {
        if (healthy) {
            unhealthySince = System.currentTimeMillis();
        }
        healthy = false;
        lastError = detail;
    }

    /**
     * Whether the daemon may replace this worker while the server connection is down:
     * never while it holds edits that are not checked in, since a new worker would not
     * have them.
     */
    private boolean replaceable() {
        GhidraContext ctx = engine.getContext();
        if (ctx.isReadOnly()) {
            return true;
        }
        for (Program p : ctx.getPrograms().values()) {
            if (p.isChanged()) {
                return false;
            }
        }
        for (DomainFile df : ctx.getServerFiles().values()) {
            try {
                if (df.isCheckedOut() && df.modifiedSinceCheckout()) {
                    return false;
                }
            } catch (Exception e) {
                return false;
            }
        }
        return true;
    }

    /** Heartbeat payload: the daemon replaces a worker that stays unhealthy and replaceable. */
    public JsonObject status() {
        JsonObject o = new JsonObject();
        o.addProperty("healthy", healthy);
        if (lastError != null) {
            o.addProperty("error", lastError);
        }
        if (unhealthySince > 0) {
            o.addProperty("unhealthySince", unhealthySince);
        }
        o.addProperty("lastProbeAt", lastProbeAt);
        if (lastRecoveredAt > 0) {
            o.addProperty("lastRecoveredAt", lastRecoveredAt);
        }
        boolean replaceable;
        try {
            replaceable = replaceable();
        } catch (Exception e) {
            replaceable = false;
        }
        o.addProperty("replaceable", replaceable);
        return o;
    }
}
