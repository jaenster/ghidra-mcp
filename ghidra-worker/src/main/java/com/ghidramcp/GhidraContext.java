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
    private final Map<String, ChangeJournal> changeJournals = new HashMap<>();
    /**
     * Applied to every change journal as its program is registered. Set once by the
     * Worker; programs open and close over a session's life, so wiring the push here
     * rather than over the map at startup is the difference between covering every
     * program and covering only the ones that happened to be open first.
     */
    private java.util.function.Consumer<java.util.List<ChangeJournal.ChangeEvent>> changeBatchListener;
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
    /** Ordered change journal for the active program, or null if none is open. */
    public ChangeJournal getChangeJournal() {
        return activeProgramPath != null ? changeJournals.get(activeProgramPath) : null;
    }
    public ChangeJournal getChangeJournal(String path) { return changeJournals.get(path); }
    public Map<String, ChangeJournal> getChangeJournals() { return changeJournals; }
    public void setChangeBatchListener(
            java.util.function.Consumer<java.util.List<ChangeJournal.ChangeEvent>> listener) {
        this.changeBatchListener = listener;
        for (ChangeJournal j : changeJournals.values()) {
            j.setBatchListener(listener);
        }
    }
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
        // Attach the ordered change journal. It runs alongside the dirty tracker rather
        // than replacing it in one step, so existing consumers keep working while the
        // live reconstruction daemon moves over to sequences.
        ChangeJournal journal = new ChangeJournal(log);
        journal.attach(prog);
        if (changeBatchListener != null) {
            journal.setBatchListener(changeBatchListener);
        }
        changeJournals.put(path, journal);
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

    // ============== Function resolution ==============

    /**
     * Resolve a function by address or by name — the single place every tool goes through, so
     * they all accept the same things.
     *
     * An address anywhere inside a function resolves to that function, not just its entry.
     * A name may be the simple name ("FN") or the fully-qualified one that list_symbols and
     * list_functions print ("Storm::Source::SFile::FN"); anything a tool emits is accepted by
     * the tools that consume it. A simple name matching several functions is an error naming
     * the candidates rather than a silent pick — duplicate names are real in stripped binaries.
     *
     * Returns null when nothing matches; use {@link #requireFunction} to get an error that
     * explains what was looked for.
     */
    public Function resolveFunction(String address, String name) {
        FunctionManager fm = program.getFunctionManager();

        if (address != null) {
            Address addr = parseAddress(address);
            if (addr == null) {
                return null;
            }
            Function f = fm.getFunctionAt(addr);
            return f != null ? f : fm.getFunctionContaining(addr);
        }
        if (name == null) {
            return null;
        }

        String wanted = name.startsWith("::") ? name.substring(2) : name;
        List<Function> simpleMatches = new ArrayList<>();
        Iterator<Function> iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName(true).equals(wanted)) {
                return func;  // fully-qualified match wins, and is never ambiguous
            }
            if (func.getName().equals(wanted)) {
                simpleMatches.add(func);
            }
        }
        if (simpleMatches.size() == 1) {
            return simpleMatches.get(0);
        }
        if (simpleMatches.size() > 1) {
            StringBuilder sb = new StringBuilder();
            sb.append('"').append(name).append("\" matches ").append(simpleMatches.size())
              .append(" functions: ");
            for (int i = 0; i < Math.min(simpleMatches.size(), 8); i++) {
                Function f = simpleMatches.get(i);
                if (i > 0) sb.append(", ");
                sb.append(f.getEntryPoint()).append(' ').append(f.getName(true));
            }
            if (simpleMatches.size() > 8) sb.append(", …");
            sb.append(". Pass the fully-qualified name, or address=.");
            throw new IllegalArgumentException(sb.toString());
        }
        return null;
    }

    /**
     * Resolve a function, or fail with a message that says what was looked for and what is
     * nearby — "Function not found" on its own sends people hunting in the wrong place.
     */
    public Function requireFunction(String address, String name) throws Exception {
        Function func = resolveFunction(address, name);
        if (func != null) {
            return func;
        }
        if (address != null) {
            Address addr = parseAddress(address);
            if (addr == null) {
                throw new Exception("Not a valid address for this program: " + address);
            }
            Function before = null;
            for (Function f : program.getFunctionManager().getFunctions(false)) {
                if (f.getEntryPoint().compareTo(addr) <= 0) {
                    before = f;
                    break;
                }
            }
            String hint = before != null
                ? " The nearest function before it is " + before.getName(true) + " at "
                  + before.getEntryPoint() + ", which ends before this address."
                : "";
            throw new Exception("No function at or containing " + address + "." + hint);
        }
        throw new Exception("No function named \"" + name + "\"." + nameSuggestion(name));
    }

    /** Up to a handful of function names containing the same text, to catch near-misses. */
    private String nameSuggestion(String name) {
        String needle = name.toLowerCase();
        int cut = needle.lastIndexOf("::");
        if (cut >= 0) {
            needle = needle.substring(cut + 2);
        }
        List<String> near = new ArrayList<>();
        Iterator<Function> iter = program.getFunctionManager().getFunctions(true);
        while (iter.hasNext() && near.size() < 5) {
            Function f = iter.next();
            if (f.getName().toLowerCase().contains(needle)) {
                near.add(f.getName(true));
            }
        }
        return near.isEmpty() ? "" : " Similar: " + String.join(", ", near) + ".";
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

        if (typeName == null || typeName.trim().isEmpty()) {
            throw new IllegalArgumentException("Data type name is empty");
        }
        String name = typeName.trim();

        // Check for array syntax: type[size]
        java.util.regex.Pattern arrayPattern = java.util.regex.Pattern.compile("^(.+?)\\[(\\d+)\\]$");
        java.util.regex.Matcher arrayMatcher = arrayPattern.matcher(name);
        if (arrayMatcher.matches()) {
            String baseTypeName = arrayMatcher.group(1);
            int arraySize = Integer.parseInt(arrayMatcher.group(2));
            DataType baseType = resolveDataType(baseTypeName);
            return new ArrayDataType(baseType, arraySize, baseType.getLength(), dtm);
        }

        // Pointer syntax ("void*", "D2UnitStrc *"). Handled before anything else so the
        // base name goes through the same resolution order.
        if (name.endsWith("*")) {
            String baseTypeName = name.substring(0, name.length() - 1).trim();
            DataType baseType = resolveDataType(baseTypeName);
            return dtm.getPointer(baseType);
        }

        // A category-qualified name is an explicit choice - look it up and nothing else.
        if (name.indexOf('/') >= 0) {
            String path = name.startsWith("/") ? name : "/" + name;
            DataType found = dtm.getDataType(path);
            if (found != null) return found;
            throw new IllegalArgumentException(
                "Unknown data type: '" + typeName + "'. Nothing lives at category path '"
                + path + "' in this program's data type manager.");
        }

        // An exact, case-sensitive match in the program's own data type manager beats the
        // builtin alias table below. The aliases are matched case-insensitively, so asking
        // for the Win32 'DWORD' used to land on the builtin 'dword' (rendered 'uint') while
        // WinDef.h/DWORD sat right there in the program, and 'ulong' used to land on an
        // 8-byte ulonglong that resizes a stack slot on a 32-bit program. Both reported
        // success. The program's own types are the more specific answer; prefer them.
        DataType exact = findExactDataType(dtm, name);
        if (exact != null) return exact;

        // Builtin aliases, matched case-insensitively. Only reached when the program has no
        // type of that exact name.
        switch (name.toLowerCase()) {
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
                break;
        }

        // Not found. Fail loudly rather than silently substituting undefined1:
        // a caller that named "D2UnitStrc *" and got a 1-byte placeholder gets a
        // success response and a corrupted type, with nothing in the reply to show
        // it. Every caller of this method (struct fields, typedef bases,
        // set_data_type, set_custom_signature return/param types,
        // set_function_variable_type) is a place where that is wrong.
        throw new IllegalArgumentException(
            "Unknown data type: '" + typeName + "'. It is not a builtin alias, not in "
            + "the program's data type manager, and not a pointer or array of one. "
            + "Note function-pointer syntax such as 'void (*)(void *)' is NOT parsed here "
            + "- create the function definition first, then refer to it by name.");
    }

    /**
     * Exact, case-sensitive lookup of a bare type name in the program's data type manager.
     * Returns null when nothing carries that name.
     *
     * When several types share the name, candidates that are equivalent to one another are
     * collapsed (the same typedef pulled in from two headers is not a conflict). If what is
     * left is still more than one genuinely different type, throw and name the candidates
     * rather than picking one - the caller can then pass the category-qualified name. A
     * silent pick between two different types is the failure this method exists to prevent.
     */
    private DataType findExactDataType(DataTypeManager dtm, String name) {
        List<DataType> all = new ArrayList<>();
        dtm.findDataTypes(name, all);
        if (all.isEmpty()) return null;

        List<DataType> named = new ArrayList<>();
        for (DataType dt : all) {
            if (dt.getName().equals(name) && !(dt instanceof Pointer) && !(dt instanceof Array)) {
                named.add(dt);
            }
        }
        if (named.isEmpty()) {
            // Only pointer/array instances carry the name - preserve the old fallback.
            return all.get(0);
        }

        List<DataType> distinct = new ArrayList<>();
        for (DataType dt : named) {
            boolean duplicate = false;
            for (DataType kept : distinct) {
                if (kept.getLength() == dt.getLength() && kept.isEquivalent(dt)) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) distinct.add(dt);
        }

        if (distinct.size() > 1) {
            StringBuilder sb = new StringBuilder();
            for (DataType dt : distinct) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(dt.getPathName()).append(" (").append(dt.getLength()).append(" bytes)");
            }
            throw new IllegalArgumentException(
                "Ambiguous data type: '" + name + "' matches " + distinct.size()
                + " different types: " + sb + ". Pass the category-qualified name "
                + "(for example '" + distinct.get(0).getPathName().replaceFirst("^/", "")
                + "') to say which one you mean.");
        }

        // Prefer the root-category instance when duplicates were collapsed, so the answer
        // is stable regardless of the order the manager happened to return them in.
        for (DataType dt : named) {
            if (dt.getCategoryPath() != null && dt.getCategoryPath().isRoot()) return dt;
        }
        return named.get(0);
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
