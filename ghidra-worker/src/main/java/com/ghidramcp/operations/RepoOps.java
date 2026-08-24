package com.ghidramcp.operations;

import com.ghidramcp.GhidraContext;
import com.ghidramcp.logging.Logger;

import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.remote.RepositoryItem;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Repository-scoped operations: everything that acts on the Ghidra Server repository
 * itself rather than on an open program — listing repos and their contents, importing
 * new binaries, deleting and moving programs.
 *
 * None of these need a program open, so a worker started in repo mode (connected to the
 * server, no --program) can serve them. Importing is the slow part, so it runs as a
 * background job: the command returns a jobId immediately unless asked to wait.
 */
public class RepoOps {
    private final GhidraContext ctx;
    private final ProjectOps projectOps;

    // Everything that needs the repository project open takes this: an import job and a
    // move/delete arriving together would otherwise fight over the project lock, since each
    // job lets go of the project when it finishes.
    private final Object projectLock = new Object();

    private final Map<String, Job> jobs = new ConcurrentHashMap<>();
    private final ExecutorService jobExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "repo-import");
        t.setDaemon(true);
        return t;
    });

    public RepoOps(GhidraContext ctx, ProjectOps projectOps) {
        this.ctx = ctx;
        this.projectOps = projectOps;
    }

    // ============== Listing ==============

    public JsonArray listRepos() throws Exception {
        RepositoryServerAdapter server = requireServer();
        JsonArray out = new JsonArray();
        for (String name : server.getRepositoryNames()) {
            out.add(name);
        }
        return out;
    }

    /**
     * Create a repository on the server. The creating user owns it, so subsequent imports
     * and check-ins work without further administration.
     *
     * There is deliberately no counterpart: Ghidra Server answers deleteRepository with
     * "Delete repository not yet implemented", so removing one means deleting its directory
     * under the server's repositories volume and restarting the server.
     */
    public JsonObject createRepo(String name) throws Exception {
        RepositoryServerAdapter server = requireServer();
        for (String existing : server.getRepositoryNames()) {
            if (existing.equals(name)) {
                throw new IOException("Repository already exists: " + name);
            }
        }
        RepositoryAdapter repo = server.createRepository(name);
        repo.connect();

        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("repo", name);
        out.addProperty("owner", server.getUser());
        ctx.getLog().info("Created repository '" + name + "'");
        return out;
    }

    /**
     * List the programs in a repository, walking it through the repository adapter so no
     * project needs to be open — this is what makes discovery possible before a session exists.
     */
    public JsonObject listRepoPrograms(String repoName, String folder, boolean recursive,
                                       String filter) throws Exception {
        if (repoName == null || repoName.isEmpty()) {
            return listAllRepoPrograms(folder, recursive, filter);
        }
        RepositoryServerAdapter server = requireServer();
        RepositoryAdapter repo = server.getRepository(repoName);
        repo.connect();
        if (!repo.isConnected()) {
            throw new IOException("Failed to connect to repository: " + repoName);
        }

        String root = (folder == null || folder.isEmpty()) ? "/" : normalizeFolder(folder);
        List<JsonObject> found = new ArrayList<>();
        collectItems(repo, root, recursive, filter, found);

        JsonObject result = new JsonObject();
        result.addProperty("repo", repoName);
        result.addProperty("folder", root);
        JsonArray arr = new JsonArray();
        for (JsonObject o : found) {
            arr.add(o);
        }
        result.add("programs", arr);
        result.addProperty("total", found.size());
        return result;
    }

    /**
     * Every program on the server, each path prefixed with its repository — which is the
     * form the tools take back, so a listing can be pasted straight into create_session.
     */
    private JsonObject listAllRepoPrograms(String folder, boolean recursive, String filter)
            throws Exception {
        RepositoryServerAdapter server = requireServer();
        JsonArray all = new JsonArray();
        JsonArray repos = new JsonArray();
        int total = 0;

        for (String name : server.getRepositoryNames()) {
            repos.add(name);
            try {
                JsonObject one = listRepoPrograms(name, folder, recursive, filter);
                for (var el : one.getAsJsonArray("programs")) {
                    JsonObject entry = el.getAsJsonObject();
                    // "Diablo2Lod/windows/1.09d/D2Game.dll" — repo-qualified, ready to open.
                    entry.addProperty("repo", name);
                    entry.addProperty("path", name + entry.get("path").getAsString());
                    all.add(entry);
                    total++;
                }
            } catch (Exception e) {
                // A repository this user cannot read must not sink the whole listing.
                ctx.getLog().warn("Skipping repository '" + name + "': " + e.getMessage());
            }
        }

        JsonObject result = new JsonObject();
        result.add("repos", repos);
        result.add("programs", all);
        result.addProperty("total", total);
        return result;
    }

    private void collectItems(RepositoryAdapter repo, String folder, boolean recursive,
                              String filter, List<JsonObject> out) throws IOException {
        for (RepositoryItem item : repo.getItemList(folder)) {
            String path = joinPath(folder, item.getName());
            if (filter != null && !path.toLowerCase().contains(filter.toLowerCase())) {
                continue;
            }
            JsonObject o = new JsonObject();
            o.addProperty("name", item.getName());
            o.addProperty("path", path);
            o.addProperty("contentType", item.getContentType());
            o.addProperty("version", item.getVersion());
            out.add(o);
        }
        if (!recursive) {
            return;
        }
        for (String sub : repo.getSubfolderList(folder)) {
            collectItems(repo, joinPath(folder, sub), true, filter, out);
        }
    }

    // ============== Import ==============

    /**
     * One binary to import: where the bytes come from and where it lands in the repo.
     */
    public static class ImportSpec {
        public String url;
        public String localPath;
        public String bytesBase64;
        public String programPath;
        public String processor;
        public String compilerSpec;
    }

    /**
     * Import one or more binaries into a repository. Returns a job descriptor; poll
     * {@link #jobStatus} for progress unless {@code wait} is set.
     */
    public JsonObject importPrograms(String repoName, List<ImportSpec> specs, boolean analyze,
                                     boolean overwrite, boolean wait, int waitTimeoutMs)
            throws Exception {
        if (specs.isEmpty()) {
            throw new IllegalArgumentException("No binaries to import");
        }
        if (ctx.isReadOnly()) {
            throw new IllegalStateException("Session is read-only; import needs a writable session");
        }
        // Fail fast on a bad spec rather than halfway through a 24-file batch.
        for (ImportSpec spec : specs) {
            if (spec.programPath == null || spec.programPath.isEmpty()) {
                throw new IllegalArgumentException("programPath is required for every import");
            }
            if (spec.url == null && spec.localPath == null && spec.bytesBase64 == null) {
                throw new IllegalArgumentException(
                        "Each import needs one of url, localPath or bytesBase64: " + spec.programPath);
            }
        }

        Job job = new Job(specs.size());
        jobs.put(job.id, job);
        jobExecutor.submit(() -> runImport(job, repoName, specs, analyze, overwrite));

        if (wait) {
            long deadline = System.currentTimeMillis() + (waitTimeoutMs > 0 ? waitTimeoutMs : 600_000);
            while (System.currentTimeMillis() < deadline && !job.finished) {
                Thread.sleep(200);
            }
        }
        return job.toJson();
    }

    public JsonObject jobStatus(String jobId) {
        Job job = jobs.get(jobId);
        if (job == null) {
            throw new IllegalArgumentException("Unknown job: " + jobId);
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

    private void runImport(Job job, String repoName, List<ImportSpec> specs, boolean analyze,
                           boolean overwrite) {
        synchronized (projectLock) {
            runImportLocked(job, repoName, specs, analyze, overwrite);
        }
    }

    private void runImportLocked(Job job, String repoName, List<ImportSpec> specs, boolean analyze,
                                 boolean overwrite) {
        Logger log = ctx.getLog();
        job.state = "running";
        try {
            projectOps.openRepoProject(repoName);
            for (ImportSpec spec : specs) {
                job.current = spec.programPath;
                try {
                    JsonObject one = importOne(spec, analyze, overwrite);
                    job.results.add(one);
                    job.done++;
                } catch (Exception e) {
                    log.error("Import failed for " + spec.programPath + ": " + e.getMessage());
                    JsonObject one = new JsonObject();
                    one.addProperty("programPath", spec.programPath);
                    one.addProperty("success", false);
                    one.addProperty("error", String.valueOf(e.getMessage()));
                    job.results.add(one);
                    job.failed++;
                }
            }
            job.state = "done";
        } catch (Exception e) {
            log.error("Import job failed: " + e.getMessage());
            job.state = "error";
            job.error = String.valueOf(e.getMessage());
        } finally {
            // Let go of the project as soon as the job is done. Holding it keeps a checkout
            // on everything imported through it, which then blocks move_program and
            // delete_program on programs no one is actually using.
            projectOps.closeRepoProject();
            job.current = null;
            job.finished = true;
        }
    }

    private JsonObject importOne(ImportSpec spec, boolean analyze, boolean overwrite)
            throws Exception {
        Logger log = ctx.getLog();
        Project project = ctx.getServerProject();
        ProjectData projectData = ctx.getProjectData();
        TaskMonitor monitor = ctx.getMonitor();

        String targetPath = normalizeProgramPath(spec.programPath);
        int slash = targetPath.lastIndexOf('/');
        String folderPath = slash <= 0 ? "/" : targetPath.substring(0, slash);
        String targetName = targetPath.substring(slash + 1);
        if (targetName.isEmpty()) {
            throw new IllegalArgumentException("programPath must end in a program name: " + spec.programPath);
        }

        DomainFile existing = projectData.getFile(targetPath);
        if (existing != null) {
            if (!overwrite) {
                throw new IOException("Program already exists (pass overwrite=true to replace): " + targetPath);
            }
            log.info("Overwriting existing program: " + targetPath);
            deleteDomainFile(existing);
        }

        Path staged = null;
        LoadResults<Program> loadResults = null;
        try {
            // Stage the bytes under the FINAL program name: Ghidra takes the program name from
            // the file it imports, so naming the temp file correctly avoids a rename afterwards.
            staged = stageSource(spec, targetName);
            DomainFolder folder = ensureFolder(projectData, folderPath);

            MessageLog msgLog = new MessageLog();
            File file = staged.toFile();
            if (spec.processor != null && !spec.processor.isEmpty()) {
                Language language = DefaultLanguageService.getLanguageService()
                        .getLanguage(new LanguageID(spec.processor));
                CompilerSpec cspec = (spec.compilerSpec != null && !spec.compilerSpec.isEmpty())
                        ? language.getCompilerSpecByID(new CompilerSpecID(spec.compilerSpec))
                        : language.getDefaultCompilerSpec();
                loadResults = AutoImporter.importByLookingForLcs(
                        file, project, folder.getPathname(), language, cspec, this, msgLog, monitor);
            } else {
                loadResults = AutoImporter.importByUsingBestGuess(
                        file, project, folder.getPathname(), this, msgLog, monitor);
            }
            if (loadResults == null || loadResults.getPrimaryDomainObject() == null) {
                throw new IOException("Import produced no program: " + msgLog);
            }

            Program program = loadResults.getPrimaryDomainObject();
            boolean analyzed = false;
            if (analyze) {
                analyzeProgram(program, monitor);
                analyzed = true;
            }

            loadResults.save(monitor);
            DomainFile df = loadResults.getPrimary().getSavedDomainFile();
            if (!df.getName().equals(targetName)) {
                df = df.setName(targetName);
            }
            String languageId = program.getLanguageID().toString();
            int functionCount = program.getFunctionManager().getFunctionCount();

            // Close the program BEFORE handing it to version control. A file that is still
            // open counts as in use, so keepCheckedOut=false could not release the checkout:
            // the import left it checked out to this worker, which then blocked a session
            // from opening it and blocked move_program with "is checked out".
            loadResults.release(this);
            loadResults = null;

            // An imported program that is only in the local project is invisible to everyone
            // else and cannot be checked out — the whole reason for importing it into a
            // shared repository. Released rather than held, so any session can take its own.
            df.addToVersionControl("Imported via ghidra-mcp", false, monitor);

            JsonObject out = new JsonObject();
            out.addProperty("programPath", repoQualified(df.getPathname()));
            out.addProperty("success", true);
            out.addProperty("analyzed", analyzed);
            out.addProperty("versioned", df.isVersioned());
            out.addProperty("version", df.getVersion());
            out.addProperty("checkedOut", df.isCheckedOut());
            try {
                out.addProperty("outstandingCheckouts", df.getCheckouts().length);
            } catch (Exception ignored) {
                // informational only
            }
            out.addProperty("languageId", languageId);
            out.addProperty("functions", functionCount);
            String warnings = msgLog.toString();
            if (warnings != null && !warnings.isBlank()) {
                out.addProperty("log", warnings.trim());
            }
            log.info("Imported " + df.getPathname() + " (" + languageId + ", checkedOut="
                    + df.isCheckedOut() + ")");
            return out;
        } finally {
            if (loadResults != null) {
                loadResults.release(this);
            }
            if (staged != null) {
                deleteStaged(staged);
            }
        }
    }

    /**
     * Run auto-analysis on a freshly imported program.
     */
    private void analyzeProgram(Program program, TaskMonitor monitor) {
        Logger log = ctx.getLog();
        int txId = program.startTransaction("Auto-analysis");
        try {
            ghidra.app.plugin.core.analysis.AutoAnalysisManager mgr =
                    ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program);
            mgr.initializeOptions();
            mgr.reAnalyzeAll(null);
            mgr.startAnalysis(monitor);
            ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(program);
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            log.error("Analysis failed: " + e.getMessage());
        }
    }

    /**
     * Fetch the binary into a temp directory, named exactly as it should land in the repo.
     * A URL is fetched by the WORKER, which is the whole point: the worker is usually on a
     * different machine than the client, so it cannot read the client's disk.
     */
    private Path stageSource(ImportSpec spec, String targetName) throws Exception {
        Path dir = Files.createTempDirectory("ghidra-mcp-import");
        Path dest = dir.resolve(targetName);

        if (spec.bytesBase64 != null) {
            Files.write(dest, Base64.getDecoder().decode(spec.bytesBase64));
            return dest;
        }
        if (spec.localPath != null) {
            Path src = Path.of(spec.localPath);
            if (!Files.isReadable(src)) {
                throw new IOException("Worker cannot read localPath (it runs on "
                        + workerLocation() + "): " + spec.localPath);
            }
            Files.copy(src, dest, StandardCopyOption.REPLACE_EXISTING);
            return dest;
        }

        URI uri = URI.create(spec.url.replace(" ", "%20"));
        // Pin HTTP/1.1: the default tries an HTTP/2 upgrade, which the daemon's own upload
        // endpoint answers by closing the connection ("header parser received no bytes").
        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        HttpRequest request = HttpRequest.newBuilder(uri).GET().build();
        HttpResponse<InputStream> response =
                client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() / 100 != 2) {
            throw new IOException("Fetch failed (HTTP " + response.statusCode() + "): " + spec.url);
        }
        try (InputStream in = response.body(); OutputStream out = Files.newOutputStream(dest)) {
            in.transferTo(out);
        }
        return dest;
    }

    private void deleteStaged(Path staged) {
        try {
            Files.deleteIfExists(staged);
            Files.deleteIfExists(staged.getParent());
        } catch (IOException ignored) {
            // temp dir cleanup is best-effort
        }
    }

    // ============== Delete / move ==============

    public JsonObject deleteProgram(String repoName, String programPath) throws Exception {
        return deleteProgram(repoName, programPath, false);
    }

    public JsonObject deleteProgram(String repoName, String programPath, boolean force) throws Exception {
        synchronized (projectLock) {
            return deleteProgramLocked(repoName, programPath, force);
        }
    }

    private JsonObject deleteProgramLocked(String repoName, String programPath, boolean force)
            throws Exception {
        projectOps.openRepoProject(repoName);
        String path = normalizeProgramPath(programPath);
        ProjectData projectData = ctx.getProjectData();
        DomainFile df = projectData.getFile(path);
        if (df == null) {
            throw new IOException("Program not found in repository " + repoName + ": " + path);
        }
        if (path.equals(ctx.getActiveProgramPath())) {
            throw new IllegalStateException("Refusing to delete the program this session has open: " + path);
        }
        if (force) {
            terminateOtherCheckouts(df);
        }
        deleteDomainFile(df);

        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("deleted", repoQualified(path));
        projectOps.closeRepoProject();
        return out;
    }

    public JsonObject moveProgram(String repoName, String fromPath, String toPath) throws Exception {
        return moveProgram(repoName, fromPath, toPath, false);
    }

    public JsonObject moveProgram(String repoName, String fromPath, String toPath, boolean force)
            throws Exception {
        synchronized (projectLock) {
            return moveProgramLocked(repoName, fromPath, toPath, force);
        }
    }

    private JsonObject moveProgramLocked(String repoName, String fromPath, String toPath,
                                         boolean force) throws Exception {
        projectOps.openRepoProject(repoName);
        String from = normalizeProgramPath(fromPath);
        String to = normalizeProgramPath(toPath);
        ProjectData projectData = ctx.getProjectData();
        TaskMonitor monitor = ctx.getMonitor();

        DomainFile df = projectData.getFile(from);
        if (df == null) {
            throw new IOException("Program not found in repository " + repoName + ": " + from);
        }
        if (projectData.getFile(to) != null) {
            throw new IOException("Target already exists: " + to);
        }
        if (from.equals(ctx.getActiveProgramPath())) {
            throw new IllegalStateException("Refusing to move the program this session has open: " + from);
        }

        if (force) {
            terminateOtherCheckouts(df);
        }

        int slash = to.lastIndexOf('/');
        String targetFolder = slash <= 0 ? "/" : to.substring(0, slash);
        String targetName = to.substring(slash + 1);

        // Neither moving nor renaming a versioned file wants a checkout — Ghidra refuses
        // both while one is outstanding. (Taking one first, as this used to, is precisely
        // what made every rename fail with "<name> is checked out".) If something else holds
        // one, say so and point at the way out.
        if (df.isCheckedOut()) {
            throw new IOException(from + " is checked out, so it cannot be moved. Close the "
                + "session using it, or pass force=true to break the checkout (losing anything "
                + "uncommitted in it).");
        }

        DomainFolder folder = ensureFolder(projectData, targetFolder);
        if (!df.getParent().getPathname().equals(folder.getPathname())) {
            df = df.moveTo(folder);
        }
        if (!df.getName().equals(targetName)) {
            df = df.setName(targetName);
        }

        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("from", repoQualified(from));
        out.addProperty("to", repoQualified(df.getPathname()));
        projectOps.closeRepoProject();
        return out;
    }

    // ============== Helpers ==============

    /**
     * Break checkouts held by other projects, so a program abandoned by a dead worker can be
     * moved or deleted. Destructive by nature — whatever was checked out and never committed
     * is lost — so it only ever happens on an explicit force.
     */
    private void terminateOtherCheckouts(DomainFile df) throws IOException {
        if (!df.isVersioned()) {
            return;
        }
        for (ghidra.framework.store.ItemCheckoutStatus checkout : df.getCheckouts()) {
            ctx.getLog().warn("Terminating checkout " + checkout.getCheckoutId() + " of "
                    + df.getPathname() + " held by " + checkout.getUser() + " (force)");
            df.terminateCheckout(checkout.getCheckoutId());
        }
        if (df.isCheckedOut()) {
            df.undoCheckout(false);
        }
    }

    private void deleteDomainFile(DomainFile df) throws IOException {
        if (df.isCheckedOut()) {
            df.undoCheckout(false);
        }
        df.delete();
    }

    private DomainFolder ensureFolder(ProjectData projectData, String folderPath) throws Exception {
        DomainFolder folder = projectData.getRootFolder();
        if (folderPath == null || folderPath.isEmpty() || folderPath.equals("/")) {
            return folder;
        }
        for (String segment : folderPath.split("/")) {
            if (segment.isEmpty()) {
                continue;
            }
            DomainFolder child = folder.getFolder(segment);
            folder = (child != null) ? child : folder.createFolder(segment);
        }
        return folder;
    }

    private RepositoryServerAdapter requireServer() throws IOException {
        RepositoryServerAdapter server = ctx.getServerAdapter();
        if (server == null || !server.isConnected()) {
            throw new IOException("Not connected to a Ghidra Server");
        }
        return server;
    }

    /** "Diablo2Lod/windows/Game.exe" — the form every tool takes back. */
    private String repoQualified(String pathname) {
        String repo = ctx.getServerRepoName();
        return repo != null ? repo + pathname : pathname;
    }

    private String workerLocation() {
        String host = ctx.getServerHost();
        return host != null ? "the worker host, connected to " + host : "the worker host";
    }

    private static String normalizeFolder(String folder) {
        String f = folder.startsWith("/") ? folder : "/" + folder;
        return (f.length() > 1 && f.endsWith("/")) ? f.substring(0, f.length() - 1) : f;
    }

    private static String normalizeProgramPath(String programPath) {
        String p = programPath.startsWith("/") ? programPath : "/" + programPath;
        return p.endsWith("/") ? p.substring(0, p.length() - 1) : p;
    }

    private static String joinPath(String folder, String name) {
        return folder.endsWith("/") ? folder + name : folder + "/" + name;
    }

    /**
     * A running or finished import. Kept in memory for the life of the worker so the
     * client can poll it after the command that started it has already returned.
     */
    private static class Job {
        final String id = UUID.randomUUID().toString().substring(0, 8);
        final int total;
        volatile String state = "queued";
        volatile String current;
        volatile String error;
        volatile boolean finished;
        volatile int done;
        volatile int failed;
        final List<JsonObject> results = new ArrayList<>();

        Job(int total) {
            this.total = total;
        }

        synchronized JsonObject toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("jobId", id);
            o.addProperty("state", state);
            o.addProperty("total", total);
            o.addProperty("done", done);
            o.addProperty("failed", failed);
            if (current != null) {
                o.addProperty("current", current);
            }
            if (error != null) {
                o.addProperty("error", error);
            }
            JsonArray arr = new JsonArray();
            for (JsonObject r : results) {
                arr.add(r);
            }
            o.add("results", arr);
            return o;
        }
    }
}
