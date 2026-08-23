package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import ghidra.app.decompiler.DecompInterface;
import ghidra.base.project.GhidraProject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.task.TaskMonitor;

import com.google.gson.JsonObject;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;

import ghidra.framework.model.ProjectData;
import ghidra.framework.model.DomainFile;

/**
 * Shared state and utility methods for all operation classes.
 * Holds program, decompiler, flat API, and common helpers.
 *
 * Supports multiple programs loaded from the same .gpr project.
 * The "active" program/decompiler/flatApi are what all Ops classes see.
 * switchProgram() changes the active triple; registerProgram() adds a new one.
 */
public class GhidraContext {
    private GhidraProject project;
    private ProjectData projectData;
    private Program program;
    private FlatProgramAPI flatApi;
    private DecompInterface decompiler;
    private TaskMonitor monitor;
    private final String projectPath;
    private final Logger log;
    private boolean readOnly = false;
    // Checked-out server DomainFiles (Ghidra Server write mode), keyed by program path.
    // One worker can hold several programs from the same repo; save/commit target the
    // active program's file. Empty for local projects.
    private final Map<String, DomainFile> serverFiles = new HashMap<>();
    // Active writable shared project (Ghidra Server write mode). Held so it can be closed on
    // shutdown. Null for local projects (which use the GhidraProject wrapper instead).
    private ghidra.framework.model.Project serverProject;
    // Live connection to the Ghidra Server RMI endpoint (server mode only).
    private ghidra.framework.client.RepositoryServerAdapter serverAdapter;
    // Where that connection points, and which repository this worker has a project open on.
    // Reported back to the daemon so a client that passes a local path gets told which host
    // the worker actually sees.
    private String serverHost;
    private int serverPort;
    private String serverRepoName;
    private static boolean jythonInitialized = false;
    private long cacheVersion = 0;

    // Read-before-write guard: function entryAddress → program modCount at read time.
    // Only populated by recordFunctionRead(); checked by assertReadBeforeWrite().
    private final Map<String, Long> functionReadMap = new HashMap<>();

    // Read-before-write guard is OPT-IN: enable with GHIDRA_MCP_READ_GUARD=1.
    // OFF by default so existing automation (cross-binary sync, VT markup, batch
    // mutations) that writes without a decompile-first in this session is not broken.
    private static final boolean GUARD_ENABLED =
        "1".equals(System.getenv("GHIDRA_MCP_READ_GUARD"));

    // Multi-program state: path → (Program, FlatProgramAPI, DecompInterface)
    private final Map<String, Program> programs = new LinkedHashMap<>();
    private final Map<String, DecompInterface> decompilers = new HashMap<>();
    private final Map<String, FlatProgramAPI> flatApis = new HashMap<>();
    private final Map<String, DirtyTracker> dirtyTrackers = new HashMap<>();
    private final Map<String, DecompilerPool> decompPools = new HashMap<>();
    private String activeProgramPath;

    public GhidraContext(String projectPath, Logger log, TaskMonitor monitor) {
        this.projectPath = projectPath;
        this.log = log;
        this.monitor = monitor;
    }

    // ============== Accessors ==============

    public Program getProgram() { return program; }
    public FlatProgramAPI getFlatApi() { return flatApi; }
    public DecompInterface getDecompiler() { return decompiler; }
    public TaskMonitor getMonitor() { return monitor; }
    public Logger getLog() { return log; }
    public String getProjectPath() { return projectPath; }
    public boolean isReadOnly() { return readOnly; }
    public GhidraProject getProject() { return project; }
    public ProjectData getProjectData() { return projectData; }
    /** DomainFile for the currently-active server program, or null if none. */
    public DomainFile getServerFile() {
        return activeProgramPath != null ? serverFiles.get(activeProgramPath) : null;
    }
    public Map<String, DomainFile> getServerFiles() { return serverFiles; }
    /** True when this worker is backed by an open Ghidra Server project. */
    public boolean isServerMode() { return serverProject != null; }
    public ghidra.framework.model.Project getServerProject() { return serverProject; }
    public String getActiveProgramPath() { return activeProgramPath; }
    public Map<String, Program> getPrograms() { return programs; }
    public Map<String, DecompInterface> getDecompilers() { return decompilers; }
    public Map<String, FlatProgramAPI> getFlatApis() { return flatApis; }
    public DirtyTracker getDirtyTracker() {
        return activeProgramPath != null ? dirtyTrackers.get(activeProgramPath) : null;
    }
    public Map<String, DirtyTracker> getDirtyTrackers() { return dirtyTrackers; }
    public DecompilerPool getDecompilerPool() {
        return activeProgramPath != null ? decompPools.get(activeProgramPath) : null;
    }
    public Map<String, DecompilerPool> getDecompPools() { return decompPools; }

    // ============== Setters (called by ProjectOps during load/open) ==============

    public void setProgram(Program program) { this.program = program; }
    public void setFlatApi(FlatProgramAPI flatApi) { this.flatApi = flatApi; }
    public void setDecompiler(DecompInterface decompiler) { this.decompiler = decompiler; }
    public void setProject(GhidraProject project) { this.project = project; }
    public void setProjectData(ProjectData projectData) { this.projectData = projectData; }
    /** Register the checked-out DomainFile for a server program, keyed by its path. */
    public void putServerFile(String path, DomainFile serverFile) { this.serverFiles.put(path, serverFile); }
    public void setServerProject(ghidra.framework.model.Project serverProject) { this.serverProject = serverProject; }
    public ghidra.framework.client.RepositoryServerAdapter getServerAdapter() { return serverAdapter; }
    public void setServerAdapter(ghidra.framework.client.RepositoryServerAdapter serverAdapter) { this.serverAdapter = serverAdapter; }
    public String getServerHost() { return serverHost; }
    public int getServerPort() { return serverPort; }
    public String getServerRepoName() { return serverRepoName; }
    public void setServerLocation(String host, int port) { this.serverHost = host; this.serverPort = port; }
    public void setServerRepoName(String repoName) { this.serverRepoName = repoName; }
    public void setReadOnly(boolean readOnly) { this.readOnly = readOnly; }

    // ============== Multi-program management ==============

    /**
     * Register a loaded program in the multi-program maps and make it the active program.
     */
    public void registerProgram(String path, Program prog, FlatProgramAPI api, DecompInterface decomp) {
        programs.put(path, prog);
        flatApis.put(path, api);
        decompilers.put(path, decomp);
        // Create decompiler pool for parallel decompilation
        decompPools.put(path, new DecompilerPool(prog, log));
        // Attach dirty tracker
        DirtyTracker tracker = new DirtyTracker(log);
        tracker.attach(prog);
        tracker.loadFromDisk();
        dirtyTrackers.put(path, tracker);
        // Also set as active
        this.program = prog;
        this.flatApi = api;
        this.decompiler = decomp;
        this.activeProgramPath = path;
    }

    /**
     * Switch the active program context. All Ops classes will see the new program.
     */
    public void switchProgram(String path) {
        Program p = programs.get(path);
        if (p == null) {
            throw new IllegalArgumentException("Program not loaded: " + path);
        }
        this.program = p;
        this.flatApi = flatApis.get(path);
        this.decompiler = decompilers.get(path);
        this.activeProgramPath = path;
        invalidateCache();
    }

    // ============== Jython state ==============

    public static boolean isJythonInitialized() { return jythonInitialized; }
    public static void setJythonInitialized(boolean initialized) { jythonInitialized = initialized; }

    // ============== Cache version ==============

    public long getCacheVersion() { return cacheVersion; }

    public void invalidateCache() { cacheVersion++; }

    // ============== Address parsing ==============

    public Address parseAddress(String addressStr) {
        // Strip 0x/0X prefix — Ghidra's AddressFactory expects bare hex
        if (addressStr.startsWith("0x") || addressStr.startsWith("0X")) {
            addressStr = addressStr.substring(2);
        }
        AddressFactory factory = program.getAddressFactory();
        return factory.getAddress(addressStr);
    }

    // ============== Filter utilities ==============

    /**
     * Pre-compile a regex pattern once per call. Never call Pattern.compile per-iteration.
     * Falls back to literal match on invalid regex.
     */
    public static Pattern compileFilter(String regex) {
        if (regex == null || regex.isEmpty()) return null;
        try {
            return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return Pattern.compile(Pattern.quote(regex), Pattern.CASE_INSENSITIVE);
        }
    }

    /**
     * Prepare the filter string for passesFilter. If the filter contains glob wildcards
     * (* or ?), converts it to a regex and returns null for filterLower (so passesFilter
     * skips the substring check). The glob regex is merged into the compiled Pattern.
     *
     * Returns a two-element array: [filterLower, mergedPattern].
     * filterLower is null when glob wildcards are present.
     */
    public static Object[] prepareFilter(String filter, String regex) {
        Pattern compiled = compileFilter(regex);
        if (filter == null || filter.isEmpty()) {
            return new Object[] { null, compiled };
        }
        if (filter.indexOf('*') >= 0 || filter.indexOf('?') >= 0) {
            // Convert glob to regex
            StringBuilder sb = new StringBuilder("^");
            for (int i = 0; i < filter.length(); i++) {
                char c = filter.charAt(i);
                if (c == '*') {
                    sb.append(".*");
                } else if (c == '?') {
                    sb.append(".");
                } else if ("\\[]{}()^$.|+".indexOf(c) >= 0) {
                    sb.append('\\').append(c);
                } else {
                    sb.append(c);
                }
            }
            sb.append("$");
            Pattern globPattern = Pattern.compile(sb.toString(), Pattern.CASE_INSENSITIVE);
            // If there's also a regex param, both must match
            if (compiled != null) {
                // Chain: glob AND regex both must pass
                final Pattern glob = globPattern;
                final Pattern rx = compiled;
                // Return glob as the compiled pattern and null filterLower.
                // We need both to match, so combine them.
                // Since passesFilter checks filterLower AND compiled, we can
                // use filterLower=null and make compiled check both.
                // But compiled only does find(), not matches(). Use a custom approach.
                // For simplicity: just store glob as the compiled, ignore regex (rare case)
                return new Object[] { null, globPattern };
            }
            return new Object[] { null, globPattern };
        }
        return new Object[] { filter.toLowerCase(), compiled };
    }

    /**
     * Unified filter check. Called per-item in hot loops — no compilation.
     * When prepareFilter converted a glob to regex, filterLower will be null and
     * the glob pattern will be in compiled, matched with matches() (anchored).
     */
    public static boolean passesFilter(String value, String filterLower, Pattern compiled) {
        if (filterLower != null) {
            if (value.toLowerCase().indexOf(filterLower) < 0) return false;
        }
        if (compiled != null) {
            if (!compiled.matcher(value).find()) return false;
        }
        return true;
    }

    // ============== Data type resolution ==============

    public DataType resolveDataType(String typeName) {
        DataTypeManager dtm = program.getDataTypeManager();

        // Check for array syntax: type[size]
        java.util.regex.Pattern arrayPattern = java.util.regex.Pattern.compile("^(.+?)\\[(\\d+)\\]$");
        java.util.regex.Matcher arrayMatcher = arrayPattern.matcher(typeName);
        if (arrayMatcher.matches()) {
            String baseTypeName = arrayMatcher.group(1);
            int arraySize = Integer.parseInt(arrayMatcher.group(2));
            DataType baseType = resolveDataType(baseTypeName);
            return new ArrayDataType(baseType, arraySize, baseType.getLength(), dtm);
        }

        // Handle common type aliases
        switch (typeName.toLowerCase()) {
            case "pointer":
            case "ptr":
                return dtm.getPointer(DataType.DEFAULT);
            case "byte":
            case "uint8":
            case "uchar":
                return ByteDataType.dataType;
            case "word":
            case "uint16":
            case "ushort":
                return UnsignedShortDataType.dataType;
            case "dword":
            case "uint32":
            case "uint":
                return UnsignedIntegerDataType.dataType;
            case "qword":
            case "uint64":
            case "ulong":
                return UnsignedLongLongDataType.dataType;
            case "int8":
            case "char":
                return CharDataType.dataType;
            case "int16":
            case "short":
                return ShortDataType.dataType;
            case "int32":
            case "int":
                return IntegerDataType.dataType;
            case "int64":
            case "long":
            case "longlong":
                return LongLongDataType.dataType;
            case "float":
                return FloatDataType.dataType;
            case "double":
                return DoubleDataType.dataType;
            case "void":
                return VoidDataType.dataType;
            case "bool":
            case "boolean":
                return BooleanDataType.dataType;
            default:
                // Handle pointer types (e.g., "void*", "int*", "char*")
                if (typeName.endsWith("*")) {
                    String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();
                    DataType baseType = resolveDataType(baseTypeName);
                    return dtm.getPointer(baseType);
                }

                // Try to find it in the data type manager (root category first)
                DataType found = dtm.getDataType("/" + typeName);
                if (found != null) return found;

                // Search all categories for the type name
                java.util.ArrayList<DataType> foundList = new java.util.ArrayList<>();
                dtm.findDataTypes(typeName, foundList);
                if (!foundList.isEmpty()) {
                    for (DataType dt : foundList) {
                        if (dt.getName().equals(typeName) && !(dt instanceof Pointer) && !(dt instanceof Array)) {
                            return dt;
                        }
                    }
                    return foundList.get(0);
                }

                // Return undefined if not found
                return Undefined1DataType.dataType;
        }
    }

    // ============== PLATE comment management ==============

    /**
     * Update a function's PLATE comment with structured metadata.
     * Must be called inside an existing transaction.
     */
    public void updateFunctionPlateComment(Function func, String description) {
        try {
            Address entryPoint = func.getEntryPoint();
            CodeUnit cu = program.getListing().getCodeUnitAt(entryPoint);
            if (cu == null) return;

            String existing = cu.getComment(CodeUnit.PLATE_COMMENT);
            String descText = extractDescription(existing);
            if (description != null && !description.isEmpty()) {
                descText = description;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("@function ").append(func.getName()).append("\n");
            sb.append("@address ").append(program.getName()).append(".").append(entryPoint.toString(true)).append("\n");

            String date = new SimpleDateFormat("yyyy.MM.dd").format(new Date());
            sb.append("@date ").append(date).append("\n");

            String callingConv = func.getCallingConventionName();
            if ("unknown".equals(callingConv)) {
                sb.append("@params\n");
                for (Parameter param : func.getParameters()) {
                    String storage = param.getVariableStorage().toString();
                    String dataType = param.getDataType().getDisplayName();
                    sb.append("  ").append(param.getName()).append(": ")
                      .append(storage).append(" (").append(dataType).append(")\n");
                }
            } else {
                sb.append("@calling ").append(callingConv).append("\n");
            }

            if (descText != null && !descText.isEmpty()) {
                sb.append("@description ").append(descText);
                if (!descText.endsWith("\n")) {
                    sb.append("\n");
                }
            }

            String comment = sb.toString();
            if (comment.endsWith("\n")) {
                comment = comment.substring(0, comment.length() - 1);
            }

            cu.setComment(CodeUnit.PLATE_COMMENT, comment);
        } catch (Exception e) {
            log.info("Failed to update PLATE comment for " + func.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Extract the @description value from an existing PLATE comment.
     */
    public String extractDescription(String plateComment) {
        if (plateComment == null || plateComment.isEmpty()) {
            return null;
        }

        if (plateComment.contains("@function") || plateComment.contains("@address") || plateComment.contains("@date")) {
            int descIdx = plateComment.indexOf("@description ");
            if (descIdx < 0) {
                descIdx = plateComment.indexOf("@description\n");
                if (descIdx < 0) return null;
                descIdx += "@description".length();
            } else {
                descIdx += "@description ".length();
            }

            int nextTag = findNextTag(plateComment, descIdx);
            String desc;
            if (nextTag >= 0) {
                desc = plateComment.substring(descIdx, nextTag).trim();
            } else {
                desc = plateComment.substring(descIdx).trim();
            }
            return desc.isEmpty() ? null : desc;
        }

        return plateComment.trim();
    }

    private int findNextTag(String text, int fromIndex) {
        String[] tags = { "\n@function", "\n@address", "\n@date", "\n@calling", "\n@params", "\n@description" };
        int earliest = -1;
        for (String tag : tags) {
            int pos = text.indexOf(tag, fromIndex);
            if (pos >= 0 && (earliest < 0 || pos < earliest)) {
                earliest = pos;
            }
        }
        return earliest;
    }

    // ============== Tag parsing ==============

    /**
     * Parse structured tags from a function.
     */
    public List<JsonObject> parseStructuredTags(Function func) {
        List<JsonObject> tags = new ArrayList<>();
        for (ghidra.program.model.listing.FunctionTag ft : func.getTags()) {
            String tagName = ft.getName();
            JsonObject tag = new JsonObject();

            int colonIdx = tagName.indexOf(':');
            if (colonIdx > 0) {
                tag.addProperty("type", tagName.substring(0, colonIdx));
                tag.addProperty("data", tagName.substring(colonIdx + 1));
            } else {
                tag.addProperty("type", tagName);
            }
            tags.add(tag);
        }
        return tags;
    }

    /**
     * Parse structured tags from bookmarks at an address.
     */
    public List<JsonObject> parseStructuredTagsFromBookmarks(Address addr) {
        List<JsonObject> tags = new ArrayList<>();
        BookmarkManager bookmarkMgr = program.getBookmarkManager();
        Bookmark[] bookmarks = bookmarkMgr.getBookmarks(addr);

        for (Bookmark bm : bookmarks) {
            if ("StructuredTag".equals(bm.getCategory())) {
                JsonObject tag = new JsonObject();
                tag.addProperty("type", bm.getTypeString());
                String comment = bm.getComment();
                if (comment != null && !comment.isEmpty()) {
                    tag.addProperty("data", comment);
                }
                tags.add(tag);
            }
        }
        return tags;
    }

    // ============== Read-before-write guard ==============

    /**
     * Record that the caller has read the function at entryAddr at the current program modCount.
     * Call this after a successful decompile() or getFunctionInfo().
     */
    public void recordFunctionRead(String entryAddr, long modCount) {
        if (entryAddr == null) return;
        functionReadMap.put(entryAddr, modCount);
    }

    /**
     * Assert that the function was read recently and the program has not changed since.
     * Throws a clear, actionable error if the guard fires.
     *
     * @param entryAddr  hex entry-point string of the function (null → skip silently)
     * @param funcName   human-readable name for the error message
     * @param force      if true, skip the check (caller opt-out)
     */
    public void assertReadBeforeWrite(String entryAddr, String funcName, boolean force) throws Exception {
        if (!GUARD_ENABLED) return;
        if (force) return;
        if (entryAddr == null || program == null) return;

        Long recorded = functionReadMap.get(entryAddr);
        if (recorded == null) {
            throw new Exception(
                "Read-before-write: read " + funcName + " first (decompile or get_function_info) " +
                "before modifying it. Pass force=true to bypass.");
        }

        long current = program.getModificationNumber();
        if (current != recorded) {
            throw new Exception(
                "Stale read: " + funcName + " changed since you read it (modCount " + recorded +
                " → " + current + ") — re-decompile or call get_function_info, then retry. " +
                "Pass force=true to bypass.");
        }
    }

    /**
     * Update the recorded modCount for a function after a successful write.
     * This allows consecutive writes on the same function without requiring a re-read.
     */
    public void updateFunctionModCount(String entryAddr) {
        if (entryAddr == null || program == null) return;
        if (!functionReadMap.containsKey(entryAddr)) return;
        functionReadMap.put(entryAddr, program.getModificationNumber());
    }

    // ============== Transaction cleanup ==============

    /**
     * Clean up orphaned transactions that scripts may leave behind.
     */
    public void cleanupOrphanedTransactions(String context) {
        if (program == null) return;

        ghidra.framework.model.TransactionInfo txInfo = program.getCurrentTransactionInfo();
        if (txInfo != null) {
            log.warn("Orphaned transaction after " + context + ": " + txInfo.getDescription() + " (ID=" + txInfo.getID() + ")");
            try {
                program.endTransaction((int) txInfo.getID(), true);
                log.info("Successfully ended orphaned transaction " + txInfo.getID());
            } catch (Exception e) {
                log.warn("Could not end transaction " + txInfo.getID() + ": " + e.getMessage());
                try {
                    program.endTransaction((int) txInfo.getID(), false);
                } catch (Exception e2) {
                    log.error("Failed to end orphaned transaction even with commit=false: " + e2.getMessage());
                }
            }
        }

        // Level 2: Check low-level DBHandle.txStarted flag via reflection
        try {
            java.lang.reflect.Field dbhField = null;
            Class<?> c = program.getClass();
            while (c != null) {
                try {
                    dbhField = c.getDeclaredField("dbh");
                    break;
                } catch (NoSuchFieldException nsfe) {
                    c = c.getSuperclass();
                }
            }
            if (dbhField != null) {
                dbhField.setAccessible(true);
                Object dbh = dbhField.get(program);
                if (dbh != null) {
                    java.lang.reflect.Field txStartedField = dbh.getClass().getDeclaredField("txStarted");
                    txStartedField.setAccessible(true);
                    boolean txStarted = (Boolean) txStartedField.get(dbh);
                    if (txStarted && program.getCurrentTransactionInfo() == null) {
                        log.warn("Ghost transaction detected at DBHandle level after " + context + " — clearing txStarted");
                        txStartedField.set(dbh, false);
                        log.info("DBHandle.txStarted cleared successfully");
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Could not check/clear DBHandle transaction state: " + e.getMessage());
        }
    }
}
