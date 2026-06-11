package com.ghidramcp.operations;

import com.ghidramcp.GhidraContext;
import com.ghidramcp.GhidraEngine;
import com.ghidramcp.logging.Logger;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraJarApplicationLayout;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Project lifecycle operations: load, open, save, close, and program info.
 * Delegates all state storage to the shared GhidraContext.
 */
public class ProjectOps {
    private final GhidraContext ctx;

    /**
     * Minimal ProjectManager that exposes DefaultProjectManager's protected constructor so we can
     * open/create a shared project as the active writable project (the same trick Ghidra's
     * HeadlessAnalyzer uses via HeadlessGhidraProjectManager).  A project opened this way is a
     * "writable project", which is required for checkout/checkin against a Ghidra Server.
     */
    private static class WorkerProjectManager extends ghidra.framework.project.DefaultProjectManager {
        WorkerProjectManager() {
            super();
        }
    }

    public ProjectOps(GhidraContext ctx) {
        this.ctx = ctx;
    }

    // ============== Static initialization ==============

    /**
     * Initialize the Ghidra application framework (once per JVM).
     * Safe to call multiple times - no-ops if already initialized.
     */
    public static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();

            // Try different layout strategies
            GhidraApplicationLayout layout;
            try {
                // First try jar layout (when running from JAR)
                layout = new GhidraJarApplicationLayout();
            } catch (Exception e) {
                // Fall back to standard layout
                File ghidraDir = new File(System.getenv("GHIDRA_HOME"));
                layout = new GhidraApplicationLayout(ghidraDir);
            }

            Application.initializeApplication(layout, config);
        }
    }

    // ============== Load / Open ==============

    /**
     * Load a program for analysis (imports a binary into a new project).
     */
    public void loadProgram(File binaryFile, boolean analyze, int analysisTimeout) throws Exception {
        Logger log = ctx.getLog();

        // Create project directory
        File projectDir = new File(ctx.getProjectPath());
        if (!projectDir.exists()) {
            projectDir.mkdirs();
        }

        // Create or open project
        String projectName = "analysis";
        GhidraProject project = GhidraProject.createProject(ctx.getProjectPath(), projectName, false);
        ctx.setProject(project);

        // Import the binary
        MessageLog msgLog = new MessageLog();
        LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(
                binaryFile, project.getProject(), "/", ctx, msgLog, ctx.getMonitor());

        if (loadResults == null || loadResults.getPrimaryDomainObject() == null) {
            throw new IOException("Failed to import binary: " + msgLog.toString());
        }
        Program program = loadResults.getPrimaryDomainObject();
        ctx.setProgram(program);

        // Initialize flat API
        ctx.setFlatApi(new FlatProgramAPI(program));

        // Run analysis if requested
        if (analyze) {
            runAnalysis();
        }

        // Initialize decompiler
        initializeDecompiler();
    }

    /**
     * Open an existing Ghidra project (.gpr file).
     * If programPath is null: auto-select if only one program, error-list if multiple.
     * If programPath is specified: load that specific program.
     */
    public void openProject(File gprFile) throws Exception {
        openProject(gprFile, null);
    }

    /**
     * Open an existing Ghidra project (.gpr file) with optional program path.
     */
    public void openProject(File gprFile, String programPath) throws Exception {
        Logger log = ctx.getLog();
        log.info("Opening existing project: " + gprFile.getAbsolutePath());

        String gprPath = gprFile.getAbsolutePath();
        if (!gprPath.endsWith(".gpr")) {
            throw new IOException("Not a Ghidra project file: " + gprPath);
        }

        File projectDir = gprFile.getParentFile();
        String projectName = gprFile.getName().replace(".gpr", "");

        GhidraProject project;
        try {
            project = GhidraProject.openProject(projectDir.getAbsolutePath(), projectName);
        } catch (Exception e) {
            // Check if this is a stale lock from a dead worker
            File lockFile = new File(projectDir, projectName + ".lock");
            if (lockFile.exists()) {
                log.warn("Project open failed, removing stale lock file: " + lockFile.getAbsolutePath());
                lockFile.delete();
                project = GhidraProject.openProject(projectDir.getAbsolutePath(), projectName);
            } else {
                throw e;
            }
        }
        ctx.setProject(project);

        Project ghidraProject = project.getProject();
        DomainFolder rootFolder = ghidraProject.getProjectData().getRootFolder();

        DomainFile programFile;
        if (programPath == null) {
            // Auto-select: find all programs
            List<DomainFile> allPrograms = findAllPrograms(rootFolder);
            if (allPrograms.isEmpty()) {
                throw new IOException("No program found in project. Project may be empty.");
            }
            if (allPrograms.size() == 1) {
                programFile = allPrograms.get(0);
            } else {
                StringBuilder sb = new StringBuilder("Multiple programs in project. Specify programPath. Available:\n");
                for (DomainFile df : allPrograms) {
                    sb.append("  ").append(df.getPathname()).append("\n");
                }
                throw new IOException(sb.toString().trim());
            }
        } else {
            programFile = findProgramByPath(rootFolder, programPath);
            if (programFile == null) {
                throw new IOException("Program not found: " + programPath);
            }
        }

        log.info("Loading program: " + programFile.getName() + " from path: " + programFile.getPathname());
        Program program = (Program) programFile.getDomainObject(ctx, true, false, ctx.getMonitor());
        ctx.setProgram(program);
        ctx.setFlatApi(new FlatProgramAPI(program));
        initializeDecompiler();

        // Register in multi-program maps
        ctx.registerProgram(programFile.getPathname(), program, ctx.getFlatApi(), ctx.getDecompiler());

        log.info("Project opened successfully");
    }

    /**
     * Open an existing Ghidra project in read-only mode.
     * This does NOT acquire an exclusive project lock, allowing concurrent access
     * with other Ghidra instances (e.g. the GUI or another MCP session).
     *
     * Note: GhidraProject.openProject(dir, name, true) does NOT actually propagate the
     * readOnly flag to DefaultProjectData, so it still tries to lock.  We bypass
     * GhidraProject entirely and use DefaultProjectData(locator, false, false) which
     * opens the project file system without acquiring the write lock.
     */
    public void openProjectReadOnly(File gprFile) throws Exception {
        openProjectReadOnly(gprFile, null);
    }

    public void openProjectReadOnly(File gprFile, String programPath) throws Exception {
        Logger log = ctx.getLog();
        log.info("Opening project read-only: " + gprFile.getAbsolutePath());
        ctx.setReadOnly(true);

        String gprPath = gprFile.getAbsolutePath();
        if (!gprPath.endsWith(".gpr")) {
            throw new IOException("Not a Ghidra project file: " + gprPath);
        }

        File projectDir = gprFile.getParentFile();
        String projectName = gprFile.getName().replace(".gpr", "");

        ProjectLocator locator = new ProjectLocator(projectDir.getAbsolutePath(), projectName);
        ProjectData projectData = new DefaultProjectData(locator, false, false);
        ctx.setProjectData(projectData);

        DomainFolder rootFolder = projectData.getRootFolder();

        DomainFile programFile;
        if (programPath == null) {
            List<DomainFile> allPrograms = findAllPrograms(rootFolder);
            if (allPrograms.isEmpty()) {
                throw new IOException("No program found in project. Project may be empty.");
            }
            if (allPrograms.size() == 1) {
                programFile = allPrograms.get(0);
            } else {
                StringBuilder sb = new StringBuilder("Multiple programs in project. Specify programPath. Available:\n");
                for (DomainFile df : allPrograms) {
                    sb.append("  ").append(df.getPathname()).append("\n");
                }
                throw new IOException(sb.toString().trim());
            }
        } else {
            programFile = findProgramByPath(rootFolder, programPath);
            if (programFile == null) {
                throw new IOException("Program not found: " + programPath);
            }
        }

        log.info("Loading program read-only: " + programFile.getName() + " from path: " + programFile.getPathname());
        Program program = (Program) programFile.getReadOnlyDomainObject(ctx, DomainFile.DEFAULT_VERSION, ctx.getMonitor());
        ctx.setProgram(program);
        ctx.setFlatApi(new FlatProgramAPI(program));
        initializeDecompiler();

        ctx.registerProgram(programFile.getPathname(), program, ctx.getFlatApi(), ctx.getDecompiler());

        log.info("Project opened read-only successfully");
    }

    // ============== Ghidra Server (remote shared project) ==============

    /**
     * Connect to a remote Ghidra Server and open a shared program from a repository.
     *
     * Authentication uses the standard Ghidra password authenticator.  Because most
     * Ghidra Servers run in fixed-identity mode (the client may NOT choose its own
     * login name — nameAllowed=false in the auth callback), the login name is derived
     * from the JVM's user.name system property.  We therefore force user.name to the
     * supplied server user id before installing the authenticator so the server sees
     * the right identity.
     *
     * When readOnly is false the program is checked out (non-exclusive) and opened
     * writable.  The working copy is backed by a persistent local shared project on the
     * pod's /data PVC so the checkout (and any unsaved edits) survive worker restarts.
     */
    public void openServerProgram(String host, int port, String repoName, String programPath,
                                  String user, char[] password, boolean readOnly) throws Exception {
        Logger log = ctx.getLog();
        log.info("Connecting to Ghidra Server " + host + ":" + port + " repo=" + repoName +
                 " program=" + programPath + " user=" + user + " readOnly=" + readOnly);

        ctx.setReadOnly(readOnly);

        // Ghidra Servers commonly reject client-supplied login names (fixed identity mode);
        // the effective login name comes from user.name.  Align it with the requested user.
        if (user != null && !user.isEmpty()) {
            System.setProperty("user.name", user);
        }

        // Use an authenticator that ALSO satisfies a server-demanded password reset.
        // Ghidra flags users created via `svrAdmin -add` (and accounts left in
        // "must change on next login" state) as needing a reset; the stock
        // PasswordClientAuthenticator only supplies the password and cannot answer
        // the reset challenge, so the worker failed to connect after a daemon restart
        // with "User password not set, must be reset". Reusing the configured password
        // as the new password completes the reset and keeps the account stable across
        // restarts (the user db lives on the persistent /repos volume).
        ghidra.framework.client.ClientUtil.setClientAuthenticator(
                new ResettingPasswordClientAuthenticator(user, new String(password)));

        ghidra.framework.client.RepositoryServerAdapter server =
                ghidra.framework.client.ClientUtil.getRepositoryServer(host, port, true);
        server.connect();
        if (!server.isConnected()) {
            throw new IOException("Failed to connect to Ghidra Server " + host + ":" + port);
        }
        ctx.setServerAdapter(server);

        ghidra.framework.client.RepositoryAdapter repo = server.getRepository(repoName);
        repo.connect();
        if (!repo.isConnected()) {
            throw new IOException("Failed to connect to repository: " + repoName);
        }
        log.info("Connected to repository '" + repoName + "', itemCount=" + repo.getItemCount());

        // Open (or create) a persistent local project on the /data PVC, linked to the repository.
        // This gives checkout/checkin a real project to work against and keeps the working copy on
        // disk across worker restarts. Root it at the PER-SESSION projects dir (ctx.getProjectPath()
        // = /data/projects/<sessionId>) rather than a single shared /data/ghidra-projects/<repo>:
        // every worker thus gets its own project dir, so two workers on the SAME repo don't fight
        // over one Ghidra project lock (each takes its own non-exclusive checkout). The sessionId is
        // stable across sticky reopens, so the working copy still survives worker/pod restarts.
        String sessionProjectPath = ctx.getProjectPath();
        File projectRoot = (sessionProjectPath != null && !sessionProjectPath.isEmpty())
                ? new File(sessionProjectPath)
                : new File("/data/ghidra-projects");
        if (!projectRoot.exists()) {
            projectRoot.mkdirs();
        }
        ProjectLocator locator = new ProjectLocator(projectRoot.getAbsolutePath(), repoName);

        // A directly-constructed DefaultProjectData is NOT a writable project, so checkout()
        // throws ReadOnlyException.  Replicate Ghidra's HeadlessAnalyzer: open the project as the
        // active writable project through a DefaultProjectManager subclass.  If the project dir
        // already exists on disk we open it (resetOwner=false, doRestore=true) to reuse the prior
        // checkout state; otherwise we create it linked to the repository.
        WorkerProjectManager pm = new WorkerProjectManager();
        Project project = openProjectRecoveringStaleLock(pm, locator, repo, projectRoot);
        ctx.setServerProject(project);
        ProjectData projectData = project.getProjectData();
        ctx.setProjectData(projectData);

        ghidra.util.task.TaskMonitor monitor = ctx.getMonitor();
        DomainFile df = projectData.getFile(programPath);
        if (df == null) {
            throw new IOException("Program not found in repository " + repoName + ": " + programPath);
        }

        Program program;
        if (readOnly) {
            program = (Program) df.getReadOnlyDomainObject(ctx, DomainFile.DEFAULT_VERSION, monitor);
        } else {
            // Check out (non-exclusive) so we can edit and later check-in new versions.
            if (df.isVersioned() && !df.isCheckedOut()) {
                log.info("Checking out (non-exclusive): " + df.getPathname());
                boolean ok = df.checkout(false, monitor);
                if (!ok) {
                    throw new IOException("Checkout failed (already checked out exclusively?): "
                                          + df.getPathname());
                }
            }
            // okToUpgrade=true: a newer Ghidra (e.g. 12.1.2 vs the 12.1 the program was
            // saved under) ships a newer processor spec, so opening triggers a minor
            // language version change (e.g. x86 4.6 -> 4.7). Permit the in-place upgrade;
            // it only persists to the repo if this working copy is later checked in.
            program = (Program) df.getDomainObject(ctx, true, false, monitor);
        }

        String path = df.getPathname();
        if (!readOnly) {
            ctx.putServerFile(path, df);
        }
        ctx.setProgram(program);
        ctx.setFlatApi(new FlatProgramAPI(program));
        initializeDecompiler();
        ctx.registerProgram(path, program, ctx.getFlatApi(), ctx.getDecompiler());

        log.info("Shared program opened successfully: " + program.getName() +
                 " (" + program.getFunctionManager().getFunctionCount() + " functions, checkedOut=" +
                 df.isCheckedOut() + ")");
    }

    /**
     * Check in (commit) the checked-out server program as a new server version.
     * Saves the working copy first, then performs a Ghidra check-in keeping the checkout
     * so editing can continue.  For a file that is in the project but not yet under version
     * control, it is added to version control instead (creates version 1).
     *
     * Returns a human-readable status string.
     */
    public String checkinServerProgram(String message) throws Exception {
        Logger log = ctx.getLog();
        DomainFile df = ctx.getServerFile();
        if (df == null) {
            throw new IllegalStateException("No checked-out server program; commit is only available "
                                            + "for writable Ghidra Server sessions.");
        }
        if (message == null || message.isEmpty()) {
            message = "MCP commit";
        }

        ghidra.util.task.TaskMonitor monitor = ctx.getMonitor();
        Program program = ctx.getProgram();

        // Flush any open transactions and persist the working copy to disk first.
        ctx.cleanupOrphanedTransactions("pre-commit");
        if (program != null && program.isChanged()) {
            program.save("MCP auto-save", monitor);
        }
        df.save(monitor);

        // File exists in the project but is not yet versioned → first check-in adds it.
        if (!df.isVersioned()) {
            log.info("Adding to version control: " + df.getPathname());
            df.addToVersionControl(message, true /*keepCheckedOut*/, monitor);
            return "Added to version control: " + df.getPathname() + " (version " + df.getVersion() + ")";
        }

        if (!df.isCheckedOut()) {
            throw new IllegalStateException("Program is not checked out; cannot check in: "
                                            + df.getPathname());
        }
        if (!df.modifiedSinceCheckout()) {
            return "Nothing to commit (no changes since checkout): " + df.getPathname();
        }

        final String comment = message;
        ghidra.framework.data.CheckinHandler handler = new ghidra.framework.data.CheckinHandler() {
            @Override
            public String getComment() { return comment; }
            @Override
            public boolean keepCheckedOut() { return true; }
            @Override
            public boolean createKeepFile() { return false; }
        };

        log.info("Checking in: " + df.getPathname() + " — " + comment);
        df.checkin(handler, monitor);
        int version = df.getVersion();
        log.info("Check-in complete: " + df.getPathname() + " version=" + version);
        return "Committed " + df.getPathname() + " as version " + version;
    }

    // ============== Save / Close ==============

    /**
     * Save the current program and project.
     * Ends any orphaned transactions before saving.
     */
    public void save() throws Exception {
        GhidraProject project = ctx.getProject();
        DomainFile serverFile = ctx.getServerFile();

        // Clean up any orphaned transactions on active program
        ctx.cleanupOrphanedTransactions("pre-save");

        // Ghidra Server (checked-out) mode: persist the working copy on disk. No GhidraProject.
        if (serverFile != null) {
            Program program = ctx.getProgram();
            if (program != null && program.isChanged()) {
                ctx.getLog().info("Saving checked-out working copy: " + serverFile.getPathname());
                program.save("MCP auto-save", ctx.getMonitor());
            }
            serverFile.save(ctx.getMonitor());
            ctx.getLog().info("Save complete (working copy)");
            return;
        }

        if (project == null) {
            throw new IllegalStateException("No project loaded");
        }

        // Save all loaded programs
        java.util.Map<String, Program> programs = ctx.getPrograms();
        if (programs.isEmpty()) {
            // Fallback: save single program (backward compat)
            Program program = ctx.getProgram();
            if (program != null) {
                ctx.getLog().info("Saving program...");
                project.save(program);
            }
        } else {
            ctx.getLog().info("Saving " + programs.size() + " program(s)...");
            for (java.util.Map.Entry<String, Program> entry : programs.entrySet()) {
                Program p = entry.getValue();
                if (p.isChanged()) {
                    ctx.getLog().info("Saving: " + entry.getKey());
                    project.save(p);
                }
            }
        }
        ctx.getLog().info("Save complete");
    }

    /**
     * Close the engine, optionally saving first.
     */
    public void close(boolean save) {
        Logger log = ctx.getLog();
        GhidraProject project = ctx.getProject();
        ProjectData projectData = ctx.getProjectData();

        // Shut down decompiler pools first
        for (com.ghidramcp.DecompilerPool pool : ctx.getDecompPools().values()) {
            pool.shutdown();
        }
        ctx.getDecompPools().clear();

        // Close all loaded programs (multi-program maps)
        java.util.Map<String, Program> programs = ctx.getPrograms();
        if (!programs.isEmpty()) {
            for (java.util.Map.Entry<String, Program> entry : programs.entrySet()) {
                String progPath = entry.getKey();
                Program prog = entry.getValue();
                DecompInterface decomp = ctx.getDecompilers().get(progPath);

                if (decomp != null) {
                    decomp.dispose();
                }

                try {
                    if (save && !ctx.isReadOnly() && project != null && !prog.isClosed()) {
                        try {
                            project.save(prog);
                        } catch (Exception e) {
                            log.error("Error saving program " + progPath + ": " + e.getMessage());
                        }
                    }
                    if (!prog.isClosed()) {
                        prog.release(ctx);
                    }
                } catch (Exception e) {
                    log.warn("Error during program release for " + progPath + ": " + e.getMessage());
                }
            }
            programs.clear();
            ctx.getDecompilers().clear();
            ctx.getFlatApis().clear();
        } else {
            // Fallback: single-program close (backward compat)
            DecompInterface decompiler = ctx.getDecompiler();
            Program program = ctx.getProgram();

            if (decompiler != null) {
                decompiler.dispose();
                ctx.setDecompiler(null);
            }

            if (program != null) {
                try {
                    if (save && !ctx.isReadOnly() && project != null && !program.isClosed()) {
                        try {
                            project.save(program);
                        } catch (Exception e) {
                            log.error("Error saving program: " + e.getMessage());
                        }
                    }
                    if (!program.isClosed()) {
                        program.release(ctx);
                    }
                } catch (Exception e) {
                    log.warn("Error during program release (may be expected): " + e.getMessage());
                }
            }
        }

        ctx.setProgram(null);
        ctx.setDecompiler(null);
        ctx.setFlatApi(null);

        if (project != null) {
            try {
                project.close();
            } catch (Exception e) {
                log.warn("Error closing project: " + e.getMessage());
            }
            ctx.setProject(null);
        }

        // Active writable shared project (Ghidra Server write mode). Closing the Project also
        // closes its underlying ProjectData, so do this instead of closing projectData directly
        // when a serverProject is held.
        Project serverProject = ctx.getServerProject();
        if (serverProject != null) {
            try {
                if (!serverProject.isClosed()) {
                    serverProject.close();
                }
            } catch (Exception e) {
                log.warn("Error closing server project: " + e.getMessage());
            }
            ctx.setServerProject(null);
            ctx.setProjectData(null);
        } else if (projectData != null) {
            try {
                projectData.close();
            } catch (Exception e) {
                log.warn("Error closing project data: " + e.getMessage());
            }
            ctx.setProjectData(null);
        }
    }

    // ============== Info ==============

    /**
     * Get program information.
     */
    public GhidraEngine.ProgramInfo getProgramInfo() {
        Program program = ctx.getProgram();

        GhidraEngine.ProgramInfo info = new GhidraEngine.ProgramInfo();
        info.name = program.getName();
        info.path = program.getExecutablePath();
        info.format = program.getExecutableFormat();
        info.languageId = program.getLanguageID().toString();
        info.compiler = program.getCompiler();

        Memory mem = program.getMemory();
        info.imageBase = program.getImageBase().toString();
        info.minAddress = mem.getMinAddress().toString();
        info.maxAddress = mem.getMaxAddress().toString();

        info.endianness = program.getLanguage().isBigEndian() ? "big" : "little";
        info.pointerSize = program.getDefaultPointerSize();

        DomainFile serverFile = ctx.getServerFile();
        if (serverFile != null) {
            info.version = serverFile.getVersion();
            info.latestVersion = serverFile.getLatestVersion();
        }

        return info;
    }

    public String[] listRepos() throws Exception {
        ghidra.framework.client.RepositoryServerAdapter server = ctx.getServerAdapter();
        if (server == null || !server.isConnected()) {
            throw new Exception("Not connected to a Ghidra Server");
        }
        return server.getRepositoryNames();
    }

    /**
     * Check if this engine was opened in read-only mode.
     */
    public boolean isReadOnly() {
        return ctx.isReadOnly();
    }

    /**
     * Check if this engine is backed by an open Ghidra Server project.
     */
    public boolean isServerMode() {
        return ctx.isServerMode();
    }

    // ============== Multi-program operations ==============

    /**
     * Load an additional program from the already-open project.
     * The project must already be open (via openProject).
     */
    public void loadAdditionalProgram(String programPath) throws Exception {
        Logger log = ctx.getLog();
        GhidraProject project = ctx.getProject();

        if (project == null) {
            throw new IllegalStateException("No project open");
        }

        // Check if already loaded
        if (ctx.getPrograms().containsKey(programPath)) {
            log.info("Program already loaded: " + programPath);
            ctx.switchProgram(programPath);
            return;
        }

        Project ghidraProject = project.getProject();
        DomainFolder rootFolder = ghidraProject.getProjectData().getRootFolder();
        DomainFile programFile = findProgramByPath(rootFolder, programPath);

        if (programFile == null) {
            throw new IOException("Program not found: " + programPath);
        }

        log.info("Loading additional program: " + programFile.getPathname());
        Program program;
        if (ctx.isReadOnly()) {
            program = (Program) programFile.getReadOnlyDomainObject(ctx, DomainFile.DEFAULT_VERSION, ctx.getMonitor());
        } else {
            program = (Program) programFile.getDomainObject(ctx, true, false, ctx.getMonitor());
        }

        FlatProgramAPI flatApi = new FlatProgramAPI(program);

        // Initialize decompiler for this program
        DecompInterface decompiler = createDecompiler(program);

        ctx.registerProgram(programFile.getPathname(), program, flatApi, decompiler);
        log.info("Additional program loaded: " + programFile.getPathname());
    }

    /**
     * Load an additional program from the already-open Ghidra Server project.
     * Reuses the project/ProjectData held on the context (no new project open, no new
     * lock), checks the program out non-exclusively if needed, and registers it in the
     * multi-program maps so CommandHandler can switch to it via _programPath.
     */
    public void loadServerProgram(String programPath) throws Exception {
        Logger log = ctx.getLog();
        ProjectData projectData = ctx.getProjectData();
        if (projectData == null || ctx.getServerProject() == null) {
            throw new IllegalStateException("No server project open");
        }

        ghidra.util.task.TaskMonitor monitor = ctx.getMonitor();
        DomainFile df = projectData.getFile(programPath);
        if (df == null) {
            throw new IOException("Program not found in server project: " + programPath);
        }
        String path = df.getPathname();

        // Already loaded → just make it active.
        if (ctx.getPrograms().containsKey(path)) {
            log.info("Server program already loaded: " + path);
            ctx.switchProgram(path);
            return;
        }

        log.info("Loading additional server program: " + path);
        Program program;
        if (ctx.isReadOnly()) {
            program = (Program) df.getReadOnlyDomainObject(ctx, DomainFile.DEFAULT_VERSION, monitor);
        } else {
            if (df.isVersioned() && !df.isCheckedOut()) {
                log.info("Checking out (non-exclusive): " + path);
                boolean ok = df.checkout(false, monitor);
                if (!ok) {
                    throw new IOException("Checkout failed (already checked out exclusively?): " + path);
                }
            }
            ctx.putServerFile(path, df);
            // okToUpgrade=true: same minor-language-upgrade handling as the primary open
            // (openServerProgram) — a newer Ghidra opening an older-saved program would otherwise
            // abort with LanguageVersionException and leave the program unregistered.
            program = (Program) df.getDomainObject(ctx, true, false, monitor);
        }

        FlatProgramAPI flatApi = new FlatProgramAPI(program);
        DecompInterface decompiler = createDecompiler(program);
        ctx.registerProgram(path, program, flatApi, decompiler);
        log.info("Additional server program loaded: " + path + " (" +
                 program.getFunctionManager().getFunctionCount() + " functions, checkedOut=" +
                 df.isCheckedOut() + ")");
    }

    /**
     * List all programs in the open project.
     */
    public JsonArray listProjectPrograms() throws Exception {
        JsonArray result = new JsonArray();

        DomainFolder rootFolder;
        if (ctx.getProject() != null) {
            rootFolder = ctx.getProject().getProject().getProjectData().getRootFolder();
        } else if (ctx.getProjectData() != null) {
            rootFolder = ctx.getProjectData().getRootFolder();
        } else {
            throw new IllegalStateException("No project open");
        }

        List<DomainFile> allPrograms = findAllPrograms(rootFolder);
        java.util.Map<String, Program> loaded = ctx.getPrograms();

        for (DomainFile df : allPrograms) {
            JsonObject entry = new JsonObject();
            entry.addProperty("name", df.getName());
            entry.addProperty("path", df.getPathname());
            entry.addProperty("loaded", loaded.containsKey(df.getPathname()));
            result.add(entry);
        }

        return result;
    }

    /**
     * Switch the active program context.
     */
    public void switchProgram(String programPath) {
        ctx.switchProgram(programPath);
    }

    // ============== Private helpers ==============

    /**
     * Open (or create) the per-session local project, auto-recovering from a stale lock.
     *
     * The project dir is per-session (/data/projects/&lt;sessionId&gt;), so the only thing that can
     * hold its lock is a prior worker JVM for THIS same session that was killed (pod restart /
     * crash) without releasing it. Recovery: kill any such leftover JVM (matched by the per-session
     * project dir on its command line, so peer-session workers on the same repo are never touched),
     * delete the lock file, and retry a few times.
     */
    private Project openProjectRecoveringStaleLock(WorkerProjectManager pm, ProjectLocator locator,
            ghidra.framework.client.RepositoryAdapter repo, File projectRoot) throws Exception {
        ghidra.framework.store.LockException last = null;
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                return locator.exists()
                        ? pm.openProject(locator, false, true)
                        : pm.createProject(locator, repo, false);
            } catch (ghidra.framework.store.LockException le) {
                last = le;
                File lockFile = locator.getProjectLockFile();
                ctx.getLog().warn("Project locked (attempt " + (attempt + 1) + "), killing any stale "
                        + "holder and clearing lock: "
                        + (lockFile != null ? lockFile.getAbsolutePath() : locator.getName())
                        + " — " + le.getMessage());
                killStaleLockHolders(projectRoot);
                if (lockFile != null && lockFile.exists()) {
                    lockFile.delete();
                }
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        throw last;
    }

    /**
     * Force-kill any OTHER JVM whose command line references this per-session project dir — i.e. a
     * dead-but-unreaped prior worker for the same session still holding the project lock. Matching on
     * the full per-session dir path (the worker's {@code --project} arg) guarantees we never kill a
     * live peer-session worker that happens to share the same repo.
     */
    private void killStaleLockHolders(File projectRoot) {
        final String dir = projectRoot.getAbsolutePath();
        final long self = ProcessHandle.current().pid();
        final Logger log = ctx.getLog();
        try {
            ProcessHandle.allProcesses()
                    .filter(ph -> ph.pid() != self)
                    .filter(ph -> ph.info().commandLine().map(cl -> cl.contains(dir)).orElse(false))
                    .forEach(ph -> {
                        log.warn("Killing stale worker holding project lock (pid=" + ph.pid()
                                + ", dir=" + dir + ")");
                        ph.destroyForcibly();
                    });
        } catch (Exception e) {
            log.warn("Could not enumerate/kill stale lock holders for " + dir + ": " + e.getMessage());
        }
    }

    /**
     * Recursively collect all Program files in a DomainFolder.
     */
    private List<DomainFile> findAllPrograms(DomainFolder folder) throws IOException {
        List<DomainFile> result = new ArrayList<>();
        collectPrograms(folder, result);
        return result;
    }

    private void collectPrograms(DomainFolder folder, List<DomainFile> result) throws IOException {
        for (DomainFile df : folder.getFiles()) {
            if (Program.class.isAssignableFrom(df.getDomainObjectClass())) {
                result.add(df);
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectPrograms(sub, result);
        }
    }

    /**
     * Find a program by its pathname in the project.
     */
    private DomainFile findProgramByPath(DomainFolder rootFolder, String programPath) throws IOException {
        List<DomainFile> all = findAllPrograms(rootFolder);
        for (DomainFile df : all) {
            if (df.getPathname().equals(programPath)) {
                return df;
            }
            // Also match by name only (for convenience)
            if (df.getName().equals(programPath)) {
                return df;
            }
        }
        return null;
    }

    /**
     * Recursively search for the first Program in a DomainFolder.
     */
    private DomainFile findFirstProgram(DomainFolder folder) throws IOException {
        // First, check files in this folder
        DomainFile[] files = folder.getFiles();

        for (DomainFile df : files) {
            if (Program.class.isAssignableFrom(df.getDomainObjectClass())) {
                return df;
            }
        }

        // Then, recursively search subfolders
        DomainFolder[] subfolders = folder.getFolders();

        for (DomainFolder subfolder : subfolders) {
            DomainFile found = findFirstProgram(subfolder);
            if (found != null) {
                return found;
            }
        }

        return null;
    }

    /**
     * Run auto-analysis on the current program.
     */
    private void runAnalysis() {
        Logger log = ctx.getLog();
        Program program = ctx.getProgram();

        log.info("Running auto-analysis...");
        int txId = program.startTransaction("Auto-analysis");
        try {
            ghidra.app.plugin.core.analysis.AutoAnalysisManager mgr =
                ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program);
            mgr.initializeOptions();
            mgr.reAnalyzeAll(null);
            mgr.startAnalysis(ctx.getMonitor());
            program.endTransaction(txId, true);
            log.info("Analysis complete");
        } catch (Exception e) {
            program.endTransaction(txId, false);
            log.error("Analysis failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Create a decompiler for a specific program (reusable for multi-program).
     */
    private DecompInterface createDecompiler(Program program) {
        return com.ghidramcp.DecompilerPool.createDecompiler(program);
    }

    /**
     * Initialize the decompiler for the active program.
     */
    private void initializeDecompiler() {
        ctx.setDecompiler(createDecompiler(ctx.getProgram()));
    }

    /**
     * A {@link ghidra.framework.client.PasswordClientAuthenticator} that also answers a
     * server-demanded password reset. Ghidra marks users created with {@code svrAdmin -add}
     * (and accounts otherwise flagged "must change on next login") as needing a reset; the
     * stock authenticator returns no new password, so the connect fails with
     * "User password not set, must be reset" — which left the worker unable to reconnect
     * after a daemon restart. We complete the reset by setting the new password to the same
     * configured GHIDRA_SERVER_PASSWORD, keeping the account usable and stable across
     * restarts (the user database is stored under the persistent /repos volume).
     */
    private static final class ResettingPasswordClientAuthenticator
            extends ghidra.framework.client.PasswordClientAuthenticator {
        private final char[] newPassword;

        ResettingPasswordClientAuthenticator(String username, String password) {
            super(username, password);
            this.newPassword = password.toCharArray();
        }

        @Override
        public char[] getNewPassword(java.awt.Component parent, String serverInfo, String username) {
            return newPassword.clone();
        }
    }
}
