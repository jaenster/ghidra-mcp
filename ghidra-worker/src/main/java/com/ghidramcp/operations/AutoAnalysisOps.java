package com.ghidramcp.operations;

import com.ghidramcp.GhidraContext;
import com.ghidramcp.logging.Logger;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Full auto-analysis of the program a session already has open.
 *
 * Analysis is the one operation that can run for many minutes on a real binary, so it
 * runs as a background job exactly like an import: the command returns a jobId at once
 * and the client polls analyze_status. What it produces is only worth having if it
 * survives the session, so the job saves the working copy and — on a Ghidra Server
 * session — checks it in as a new version.
 *
 * While a job runs the program is being rewritten under the dispatcher, so
 * {@link #isRunning()} lets the dispatcher turn every other command away until it
 * finishes; analyze_status is the exception, since it only reads the job record.
 */
public class AutoAnalysisOps {
    private final GhidraContext ctx;
    private final ProjectOps projectOps;

    private final Map<String, Job> jobs = new ConcurrentHashMap<>();
    private final AtomicReference<Job> active = new AtomicReference<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "auto-analysis");
        t.setDaemon(true);
        return t;
    });

    public AutoAnalysisOps(GhidraContext ctx, ProjectOps projectOps) {
        this.ctx = ctx;
        this.projectOps = projectOps;
    }

    /** What a caller asks for; every field has a usable default. */
    public static class Request {
        public boolean force = false;
        public boolean save = true;
        public boolean commit = true;
        public String commitMessage = "Auto-analysis";
        public long timeoutMs = 0;  // 0 = no timeout
    }

    /**
     * Start an analysis job. Returns the job as soon as it is queued unless {@code wait}
     * asks to hold on until it finishes.
     */
    public JsonObject analyze(Request req, boolean wait, long waitTimeoutMs) throws Exception {
        Program program = ctx.getProgram();
        if (program == null) {
            throw new IllegalStateException(
                "No program open. Open one with create_session (or load_program) before analyzing.");
        }
        if (ctx.isReadOnly()) {
            throw new IllegalStateException(
                "Session is read-only; analysis writes to the program. Reopen it writable.");
        }
        Job running = active.get();
        if (running != null && !running.finished) {
            throw new IllegalStateException(
                "Analysis already running (job " + running.id + "); poll analyze_status.");
        }

        Job job = new Job(program.getName(), req);
        jobs.put(job.id, job);

        if (!req.force && GhidraProgramUtilities.isAnalyzed(program)) {
            job.state = "skipped";
            job.message = "Program is already analyzed; pass force to analyze it again.";
            job.finish();
            return job.toJson();
        }

        active.set(job);
        executor.submit(() -> run(job, req));

        if (wait) {
            long deadline = System.currentTimeMillis() + (waitTimeoutMs > 0 ? waitTimeoutMs : 900_000);
            while (System.currentTimeMillis() < deadline && !job.finished) {
                Thread.sleep(200);
            }
        }
        return job.toJson();
    }

    /**
     * Start analysis and block until it is done. Used by the worker's --analyze flag, which
     * has no client to poll on its behalf.
     */
    public JsonObject analyzeBlocking(Request req, long timeoutMs) throws Exception {
        return analyze(req, true, timeoutMs);
    }

    public JsonObject status(String jobId) {
        Job job = jobs.get(jobId);
        if (job == null) {
            throw new IllegalArgumentException("Unknown analysis job: " + jobId);
        }
        return job.toJson();
    }

    public JsonArray listJobs() {
        JsonArray out = new JsonArray();
        for (Job job : jobs.values()) {
            out.add(job.toJson());
        }
        return out;
    }

    /** True while a job is rewriting the program. */
    public boolean isRunning() {
        Job job = active.get();
        return job != null && !job.finished;
    }

    /** The job currently rewriting the program, for an error message; null when idle. */
    public String runningJobId() {
        Job job = active.get();
        return (job != null && !job.finished) ? job.id : null;
    }

    private void run(Job job, Request req) {
        Logger log = ctx.getLog();
        Program program = ctx.getProgram();
        job.state = "running";
        job.functionsBefore = program.getFunctionManager().getFunctionCount();
        job.symbolsBefore = program.getSymbolTable().getNumSymbols();

        JobMonitor progress = new JobMonitor(job);
        TimeoutTaskMonitor timeout = req.timeoutMs > 0
            ? TimeoutTaskMonitor.timeoutIn(req.timeoutMs, TimeUnit.MILLISECONDS, progress)
            : null;
        TaskMonitor monitor = timeout != null ? timeout : progress;

        try {
            int txId = program.startTransaction("Auto-analysis");
            boolean ok = false;
            try {
                AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                mgr.initializeOptions();
                mgr.reAnalyzeAll(null);
                mgr.startAnalysis(monitor);
                GhidraProgramUtilities.markProgramAnalyzed(program);
                ok = true;
            } finally {
                program.endTransaction(txId, ok);
            }

            job.functionsAfter = program.getFunctionManager().getFunctionCount();
            job.symbolsAfter = program.getSymbolTable().getNumSymbols();

            boolean timedOut = timeout != null && timeout.didTimeout();
            if (timedOut) {
                job.error = "Analysis hit its " + req.timeoutMs + "ms timeout and was cancelled; "
                          + "partial results were kept.";
            }
            log.info("Analysis finished: " + job.functionsBefore + " -> "
                     + job.functionsAfter + " functions");

            persist(job, req);

            if (!"failed".equals(job.state)) {
                job.state = timedOut ? "timeout" : "done";
            }
        } catch (Exception e) {
            job.state = "failed";
            job.error = e.getMessage();
            log.error("Analysis failed: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (timeout != null) {
                timeout.finished();
            }
            ctx.invalidateCache();
            job.finish();
        }
    }

    /**
     * Save, and check in when the session came from a Ghidra Server. A worker that is
     * closed without this throws the analysis away with its project directory.
     */
    private void persist(Job job, Request req) {
        Logger log = ctx.getLog();
        if (req.save) {
            try {
                projectOps.save();
                job.saved = true;
            } catch (Exception e) {
                job.state = "failed";
                job.error = "Analysis finished but saving failed: " + e.getMessage();
                log.error("Save after analysis failed: " + e.getMessage());
                return;
            }
        }
        if (!req.commit) {
            return;
        }
        if (ctx.getServerFile() == null) {
            job.commitSkipped = "not a Ghidra Server session";
            return;
        }
        try {
            job.commitResult = projectOps.checkinServerProgram(
                req.commitMessage != null && !req.commitMessage.isEmpty()
                    ? req.commitMessage : "Auto-analysis");
            job.committed = true;
        } catch (Exception e) {
            job.commitSkipped = e.getMessage();
            log.warn("Check-in after analysis failed: " + e.getMessage());
        }
    }

    /** Feeds Ghidra's analysis progress into the job so a poll can report it. */
    private static class JobMonitor extends WrappingTaskMonitor {
        private final Job job;

        JobMonitor(Job job) {
            super(TaskMonitor.DUMMY);
            this.job = job;
        }

        @Override
        public void setMessage(String message) {
            job.message = message;
            super.setMessage(message);
        }

        @Override
        public void initialize(long max) {
            job.maximum = max;
            job.progress = 0;
            super.initialize(max);
        }

        @Override
        public synchronized void setMaximum(long max) {
            job.maximum = max;
            super.setMaximum(max);
        }

        @Override
        public void setProgress(long value) {
            job.progress = value;
            super.setProgress(value);
        }

        @Override
        public void incrementProgress(long incr) {
            job.progress += incr;
            super.incrementProgress(incr);
        }
    }

    /**
     * A running or finished analysis. Kept for the life of the worker so the client can
     * poll it long after the command that started it returned.
     */
    private static class Job {
        final String id = UUID.randomUUID().toString().substring(0, 8);
        final String program;
        final boolean forced;
        final long startedAt = System.currentTimeMillis();
        volatile String state = "queued";
        volatile String message;
        volatile String error;
        volatile boolean finished;
        volatile long finishedAt;
        volatile long progress;
        volatile long maximum;
        volatile int functionsBefore;
        volatile int functionsAfter;
        volatile int symbolsBefore;
        volatile int symbolsAfter;
        volatile boolean saved;
        volatile boolean committed;
        volatile String commitResult;
        volatile String commitSkipped;

        Job(String program, Request req) {
            this.program = program;
            this.forced = req.force;
        }

        void finish() {
            finishedAt = System.currentTimeMillis();
            finished = true;
        }

        synchronized JsonObject toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("jobId", id);
            o.addProperty("state", state);
            o.addProperty("program", program);
            o.addProperty("forced", forced);
            o.addProperty("finished", finished);
            o.addProperty("elapsedMs", (finished ? finishedAt : System.currentTimeMillis()) - startedAt);
            if (message != null) {
                o.addProperty("message", message);
            }
            if (maximum > 0) {
                o.addProperty("progress", progress);
                o.addProperty("maximum", maximum);
            }
            if (!"queued".equals(state) && !"skipped".equals(state)) {
                o.addProperty("functionsBefore", functionsBefore);
                o.addProperty("functionsAfter", functionsAfter);
                o.addProperty("symbolsBefore", symbolsBefore);
                o.addProperty("symbolsAfter", symbolsAfter);
            }
            o.addProperty("saved", saved);
            o.addProperty("committed", committed);
            if (commitResult != null) {
                o.addProperty("commitResult", commitResult);
            }
            if (commitSkipped != null) {
                o.addProperty("commitSkipped", commitSkipped);
            }
            if (error != null) {
                o.addProperty("error", error);
            }
            return o;
        }
    }
}
