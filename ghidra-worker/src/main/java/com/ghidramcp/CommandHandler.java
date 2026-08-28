package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Function;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Handles commands from the daemon and dispatches them to the GhidraEngine.
 */
public class CommandHandler {
    private static final Gson gson = new GsonBuilder().serializeNulls().create();
    private final GhidraEngine engine;
    private final Logger log;

    public CommandHandler(GhidraEngine engine, Logger log) {
        this.engine = engine;
        this.log = log;
    }

    /**
     * Handle a command and return the result
     */
    public JsonObject handle(String command, JsonObject params) throws Exception {
        // Program routing: switch active program before dispatching
        if (params.has("_programPath") && !params.get("_programPath").isJsonNull()) {
            engine.switchProgram(params.get("_programPath").getAsString());
        }

        switch (command) {
            case "list_programs":
                return handleListPrograms(params);

            case "load_program":
                return handleLoadProgram(params);

            case "get_program_info":
                return handleGetProgramInfo();

            case "list_repos":
                return handleListRepos();

            case "create_repo":
                return handleCreateRepo(params);

            case "import_program":
                return handleImportProgram(params);

            case "import_status":
                return handleImportStatus(params);

            case "delete_program":
                return handleDeleteProgram(params);

            case "move_program":
                return handleMoveProgram(params);

            case "list_checkouts":
                return handleListCheckouts(params);

            case "terminate_checkout":
                return handleTerminateCheckout(params);

            case "list_functions":
                return handleListFunctions(params);

            case "get_function_info":
                return handleGetFunctionInfo(params);

            case "decompile":
                return handleDecompile(params);

            case "batch_decompile":
                return handleBatchDecompile(params);

            case "get_xrefs":
                return handleGetXrefs(params);

            case "list_strings":
                return handleListStrings(params);

            case "list_segments":
                return handleListSegments();

            case "list_imports":
                return handleListImports(params);

            case "list_exports":
                return handleListExports(params);

            case "list_namespaces":
                return handleListNamespaces(params);

            case "read_memory":
                return handleReadMemory(params);

            case "get_hexdump":
                return handleGetHexdump(params);

            case "rename_symbol":
                return handleRenameSymbol(params);

            case "set_comment":
                return handleSetComment(params);

            case "search":
                return handleSearch(params);

            case "save":
                return handleSave();

            case "checkin":
            case "commit":
                return handleCheckin(params);

            case "create_structure":
                return handleCreateStructure(params);

            case "export_type_archive":
                return handleExportTypeArchive(params);

            case "import_type_archive":
                return handleImportTypeArchive(params);

            case "list_symbols":
                return handleListSymbols(params);

            case "get_disassembly":
                return handleGetDisassembly(params);

            case "get_function_summary":
                return handleGetFunctionSummary(params);

            case "list_data_types":
                return handleListDataTypes(params);

            case "get_data_type":
                return handleGetDataType(params);

            case "list_comments":
                return handleListComments(params);

            case "list_bookmarks":
                return handleListBookmarks(params);

            case "get_basic_blocks":
                return handleGetBasicBlocks(params);

            case "get_call_graph":
                return handleGetCallGraph(params);

            case "find_call_path":
                return handleFindCallPath(params);

            case "get_xrefs_with_context":
                return handleGetXrefsWithContext(params);

            case "get_class_info":
                return handleGetClassInfo(params);

            case "get_pcode":
                return handleGetPcode(params);

            case "batch_pcode":
                return handleBatchPcode(params);

            case "set_data_type":
                return handleSetDataType(params);

            case "set_prototype":
                return handleSetPrototype(params);

            case "set_custom_signature":
                return handleSetCustomSignature(params);

            case "batch_rename":
                return handleBatchRename(params);

            case "find_functions_matching":
                return handleFindFunctionsMatching(params);

            case "trace_data_flow":
                return handleTraceDataFlow(params);

            case "get_analysis_hints":
                return handleGetAnalysisHints(params);

            case "execute_script":
                return handleExecuteScript(params);

            case "get_line_mappings":
                return handleGetLineMappings(params);

            case "get_global_variables":
                return handleGetGlobalVariables(params);

            case "read_data_value":
                return handleReadDataValue(params);

            // Bookmark management
            case "add_bookmark":
                return handleAddBookmark(params);

            case "delete_bookmark":
                return handleDeleteBookmark(params);

            case "delete_comment":
                return handleDeleteComment(params);

            // Label management
            case "create_label":
                return handleCreateLabel(params);

            case "delete_label":
                return handleDeleteLabel(params);

            // Function management
            case "create_function":
                return handleCreateFunction(params);

            case "delete_function":
                return handleDeleteFunction(params);

            // Data type creation
            case "create_enum":
                return handleCreateEnum(params);

            case "create_union":
                return handleCreateUnion(params);

            case "create_typedef":
                return handleCreateTypedef(params);

            case "create_funcdef":
                return handleCreateFuncdef(params);

            case "update_structure":
                return handleUpdateStructure(params);

            case "delete_data_type":
                return handleDeleteDataType(params);

            // Code manipulation
            case "disassemble":
                return handleDisassemble(params);

            case "clear_listing":
                return handleClearListing(params);

            case "set_function_variable_name":
                return handleSetFunctionVariableName(params);

            case "set_function_variable_type":
                return handleSetFunctionVariableType(params);

            // Equate management
            case "list_equates":
                return handleListEquates(params);

            case "set_equate":
                return handleSetEquate(params);

            case "delete_equate":
                return handleDeleteEquate(params);

            // Function attributes/tags
            case "set_function_attributes":
                return handleSetFunctionAttributes(params);

            case "add_function_tag":
                return handleAddFunctionTag(params);

            case "remove_function_tag":
                return handleRemoveFunctionTag(params);

            case "batch_tag_symbols":
                return handleBatchTagSymbols(params);

            // Namespace management
            case "create_namespace":
                return handleCreateNamespace(params);

            case "move_symbol_to_namespace":
                return handleMoveSymbolToNamespace(params);

            case "rename_namespace":
                return handleRenameNamespace(params);

            case "delete_namespace":
                return handleDeleteNamespace(params);

            // Undo/redo
            case "undo":
                return handleUndo();

            case "redo":
                return handleRedo();

            case "get_undo_history":
                return handleGetUndoHistory();

            // Analysis
            case "get_stack_frame":
                return handleGetStackFrame(params);

            case "reanalyze":
                return handleReanalyze(params);

            // Switch table
            case "get_switch_table":
                return handleGetSwitchTable(params);
            case "set_switch_override":
                return handleSetSwitchOverride(params);

            case "get_data_at_address":
                return handleGetDataAtAddress(params);

            case "get_symbol_after":
                return handleGetSymbolAfter(params);

            case "detect_table":
                return handleDetectTable(params);

            case "export_all_c":
                return handleExportAllC(params);

            case "get_cache_version":
                return handleGetCacheVersion();

            // Version Tracking
            case "vt_create_session":
                return handleVtCreateSession(params);

            case "vt_run_correlator":
                return handleVtRunCorrelator(params);

            case "vt_list_matches":
                return handleVtListMatches(params);

            case "vt_accept_matches":
                return handleVtAcceptMatches(params);

            case "vt_apply_markup":
                return handleVtApplyMarkup();

            case "vt_get_correlators":
                return handleVtGetCorrelators();

            case "get_dirty_symbols":
                return handleGetDirtySymbols();

            case "mark_clean":
                return handleMarkClean();

            default:
                throw new UnsupportedOperationException("Unknown command: " + command);
        }
    }

    private JsonObject handleGetProgramInfo() {
        GhidraEngine.ProgramInfo info = engine.getProgramInfo();
        return gson.toJsonTree(info).getAsJsonObject();
    }

    private JsonObject handleListRepos() throws Exception {
        String[] repos = engine.listRepos();
        JsonObject result = new JsonObject();
        result.add("repos", gson.toJsonTree(repos));
        return result;
    }

    private JsonObject handleCreateRepo(JsonObject params) throws Exception {
        String name = getString(params, "name", null);
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("name is required");
        }
        return engine.repo().createRepo(name);
    }

    private JsonObject handleImportProgram(JsonObject params) throws Exception {
        String repo = getString(params, "repo", null);
        List<com.ghidramcp.operations.RepoOps.ImportSpec> specs = new ArrayList<>();
        if (params.has("items") && params.get("items").isJsonArray()) {
            for (var el : params.getAsJsonArray("items")) {
                specs.add(parseImportSpec(el.getAsJsonObject()));
            }
        } else {
            specs.add(parseImportSpec(params));
        }
        // A programPath names its repository first ("Diablo2Lod/windows/Game.exe"), which is
        // the same form create_session and the listings use. An explicit repo overrides it.
        //
        // Only the caller's repo overrides: reading the repo off item 1 and then feeding it
        // back in as the override made every later item repo-relative, so a batch of
        // repository-first paths landed under Repo/Repo/....
        String explicitRepo = repo;
        for (com.ghidramcp.operations.RepoOps.ImportSpec spec : specs) {
            String[] split = splitRepoPath(spec.programPath, explicitRepo);
            if (repo == null) {
                repo = split[0];
            } else if (!repo.equals(split[0])) {
                throw new IllegalArgumentException("All items in one import must target repo '"
                    + repo + "', but " + spec.programPath + " targets '" + split[0] + "'");
            }
            spec.programPath = split[1];
        }
        if (repo == null) {
            throw new IllegalArgumentException(
                "No repository: give programPath as \"Repo/path/to/program\", or pass repo.");
        }

        boolean analyze = getBoolean(params, "analyze", true);
        boolean overwrite = getBoolean(params, "overwrite", false);
        boolean wait = getBoolean(params, "wait", false);
        int waitTimeout = getInt(params, "waitTimeout", 0);
        return engine.repo().importPrograms(repo, specs, analyze, overwrite, wait, waitTimeout);
    }

    private com.ghidramcp.operations.RepoOps.ImportSpec parseImportSpec(JsonObject o) {
        com.ghidramcp.operations.RepoOps.ImportSpec spec =
            new com.ghidramcp.operations.RepoOps.ImportSpec();
        spec.url = getString(o, "url", null);
        spec.localPath = getString(o, "localPath", null);
        spec.bytesBase64 = getString(o, "bytesBase64", null);
        spec.programPath = getString(o, "programPath", null);
        spec.processor = getString(o, "processor", null);
        spec.compilerSpec = getString(o, "compilerSpec", null);
        return spec;
    }

    private JsonObject handleImportStatus(JsonObject params) {
        String jobId = getString(params, "jobId", null);
        if (jobId == null) {
            JsonObject result = new JsonObject();
            result.add("jobs", engine.repo().listJobs());
            return result;
        }
        return engine.repo().jobStatus(jobId);
    }

    private JsonObject handleDeleteProgram(JsonObject params) throws Exception {
        String programPath = getString(params, "programPath", null);
        if (programPath == null) {
            throw new IllegalArgumentException("programPath is required");
        }
        String[] split = splitRepoPath(programPath, getString(params, "repo", null));
        return engine.repo().deleteProgram(split[0], split[1], getBoolean(params, "force", false));
    }

    private JsonObject handleMoveProgram(JsonObject params) throws Exception {
        String from = getString(params, "from", null);
        String to = getString(params, "to", null);
        if (from == null || to == null) {
            throw new IllegalArgumentException("from and to are required");
        }
        // Both paths are read the same way: repository-first, or repo-relative when an
        // explicit repo is given. Passing `from`'s repo as the override for `to` made a
        // repo-first destination be taken as a path, producing Repo/Repo/....
        String repo = getString(params, "repo", null);
        String[] fromSplit = splitRepoPath(from, repo);
        String[] toSplit = splitRepoPath(to, repo);
        if (!fromSplit[0].equals(toSplit[0])) {
            throw new IllegalArgumentException("A move stays within one repository: "
                + fromSplit[0] + " -> " + toSplit[0]);
        }
        return engine.repo().moveProgram(fromSplit[0], fromSplit[1], toSplit[1],
                                         getBoolean(params, "force", false));
    }

    private JsonObject handleListCheckouts(JsonObject params) throws Exception {
        String programPath = getString(params, "programPath", null);
        String repo = getString(params, "repo", null);
        // With a program named, the repository comes from it exactly as everywhere else;
        // without one, a bare repo (or nothing at all, meaning every repo) is the scope.
        if (programPath != null) {
            String[] split = splitRepoPath(programPath, repo);
            return engine.repo().listCheckouts(split[0], split[1], null);
        }
        return engine.repo().listCheckouts(repo, null, getString(params, "filter", null));
    }

    private JsonObject handleTerminateCheckout(JsonObject params) throws Exception {
        String programPath = getString(params, "programPath", null);
        if (programPath == null) {
            throw new IllegalArgumentException("programPath is required");
        }
        String[] split = splitRepoPath(programPath, getString(params, "repo", null));
        Long checkoutId = null;
        if (params.has("checkoutId") && !params.get("checkoutId").isJsonNull()) {
            checkoutId = params.get("checkoutId").getAsLong();
        }
        return engine.repo().terminateCheckout(split[0], split[1], checkoutId);
    }

    /**
     * Split "Repo/path/to/program" into its repository and the path within it. With an
     * explicit repo the whole string is already the path within that repo.
     */
    private String[] splitRepoPath(String path, String explicitRepo) {
        if (path == null) {
            throw new IllegalArgumentException("A program path is required");
        }
        String trimmed = path.startsWith("/") ? path.substring(1) : path;
        if (explicitRepo != null && !explicitRepo.isEmpty()) {
            return new String[] { explicitRepo, "/" + trimmed };
        }
        int slash = trimmed.indexOf('/');
        if (slash <= 0 || slash == trimmed.length() - 1) {
            throw new IllegalArgumentException("Program path must name its repository first, as "
                + "\"Repo/path/to/program\" (got \"" + path + "\"). list_repos shows what is there.");
        }
        return new String[] { trimmed.substring(0, slash), trimmed.substring(slash) };
    }

    private JsonObject handleListFunctions(JsonObject params) {
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 100);
        String filter = getString(params, "filter", null);
        String regex = getString(params, "regex", null);
        String namespace = getString(params, "namespace", null);
        boolean includeChildren = getBoolean(params, "includeChildren", false);

        GhidraEngine.ListFunctionsResult listResult = engine.listFunctions(offset, limit, filter, regex, namespace, includeChildren);

        JsonObject result = new JsonObject();
        result.add("functions", gson.toJsonTree(listResult.functions));
        result.addProperty("total", listResult.total);
        return result;
    }

    private JsonObject handleGetFunctionInfo(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);

        Function func = engine.requireFunction(address, name);

        GhidraEngine.FunctionInfo info = engine.getFunctionInfo(func);
        return gson.toJsonTree(info).getAsJsonObject();
    }

    private JsonObject handleDecompile(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);
        int timeout = getInt(params, "timeout", 30);
        log.debug("decompile: address=" + address + " name=" + name + " timeout=" + timeout);

        Function func = engine.requireFunction(address, name);

        GhidraEngine.DecompileResult result = engine.decompile(func, timeout);
        return gson.toJsonTree(result).getAsJsonObject();
    }

    private JsonObject handleBatchDecompile(JsonObject params) {
        log.debug("batch_decompile: " +
            (params.has("addresses") ? params.getAsJsonArray("addresses").size() + " addresses" : "") +
            (params.has("names") ? params.getAsJsonArray("names").size() + " names" : ""));
        List<String> addresses = null;
        List<String> names = null;

        if (params.has("addresses") && !params.get("addresses").isJsonNull()) {
            addresses = new ArrayList<>();
            for (var el : params.getAsJsonArray("addresses")) {
                addresses.add(el.getAsString());
            }
        }
        if (params.has("names") && !params.get("names").isJsonNull()) {
            names = new ArrayList<>();
            for (var el : params.getAsJsonArray("names")) {
                names.add(el.getAsString());
            }
        }

        String filter = getString(params, "filter", null);
        String regex = getString(params, "regex", null);
        String namespace = getString(params, "namespace", null);
        String startAddress = getString(params, "startAddress", null);
        String endAddress = getString(params, "endAddress", null);
        int limit = getInt(params, "limit", 50);
        // Only cap limit for filter-based selection; explicit addresses/names bypass the cap
        if (addresses == null && names == null && limit > 200) limit = 200;
        int decompileTimeout = getInt(params, "decompileTimeout", 30);
        boolean simplify = getBoolean(params, "simplify", true);

        GhidraEngine.BatchDecompileResult batchResult = engine.batchDecompile(
            addresses, names, filter, regex, namespace, startAddress, endAddress,
            limit, decompileTimeout, simplify
        );

        return gson.toJsonTree(batchResult).getAsJsonObject();
    }

    private JsonObject handleGetXrefs(JsonObject params) {
        String address = getString(params, "address", null);
        String direction = getString(params, "direction", "both");
        int limit = getInt(params, "limit", 50);
        List<String> refTypes = parseStringOrArray(params, "refType");

        List<GhidraEngine.XRef> xrefs = engine.getXrefs(address, direction, limit, refTypes);

        JsonObject result = new JsonObject();
        result.add("xrefs", gson.toJsonTree(xrefs));
        return result;
    }

    private JsonObject handleListStrings(JsonObject params) {
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 100);
        int minLength = getInt(params, "minLength", 4);
        String filter = getString(params, "filter", null);
        String regex = getString(params, "regex", null);

        List<GhidraEngine.StringInfo> strings = engine.listStrings(offset, limit, minLength, filter, regex);

        JsonObject result = new JsonObject();
        result.add("strings", gson.toJsonTree(strings));
        result.addProperty("total", strings.size());
        return result;
    }

    private JsonObject handleListSegments() {
        List<GhidraEngine.SegmentInfo> segments = engine.listSegments();

        JsonObject result = new JsonObject();
        result.add("segments", gson.toJsonTree(segments));
        return result;
    }

    private JsonObject handleListImports(JsonObject params) {
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 100);
        String filter = getString(params, "filter", null);
        String regex = getString(params, "regex", null);

        List<GhidraEngine.ImportInfo> imports = engine.listImports(offset, limit, filter, regex);

        JsonObject result = new JsonObject();
        result.add("imports", gson.toJsonTree(imports));
        result.addProperty("total", imports.size());
        return result;
    }

    private JsonObject handleListExports(JsonObject params) {
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 100);
        String filter = getString(params, "filter", null);
        String regex = getString(params, "regex", null);

        List<GhidraEngine.ExportInfo> exports = engine.listExports(offset, limit, filter, regex);

        JsonObject result = new JsonObject();
        result.add("exports", gson.toJsonTree(exports));
        result.addProperty("total", exports.size());
        return result;
    }

    private JsonObject handleListNamespaces(JsonObject params) {
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 100);
        String filter = getString(params, "filter", null);
        String regex = getString(params, "regex", null);

        List<GhidraEngine.NamespaceInfo> namespaces = engine.listNamespaces(offset, limit, filter, regex);

        JsonObject result = new JsonObject();
        result.add("namespaces", gson.toJsonTree(namespaces));
        result.addProperty("total", namespaces.size());
        return result;
    }

    private JsonObject handleReadMemory(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        int length = getInt(params, "length", 0);

        if (address == null || length <= 0) {
            throw new IllegalArgumentException("address and length are required");
        }

        byte[] bytes = engine.readMemory(address, length);

        JsonObject result = new JsonObject();
        result.addProperty("address", address);
        result.addProperty("bytes", Base64.getEncoder().encodeToString(bytes));
        result.addProperty("length", bytes.length);
        return result;
    }

    private JsonObject handleGetHexdump(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        int length = getInt(params, "length", 0);
        int bytesPerLine = getInt(params, "bytesPerLine", 16);

        if (address == null || length <= 0) {
            throw new IllegalArgumentException("address and length are required");
        }

        byte[] bytes = engine.readMemory(address, length);
        String hexdump = formatHexdump(bytes, bytesPerLine);

        JsonObject result = new JsonObject();
        result.addProperty("address", address);
        result.addProperty("hexdump", hexdump);
        return result;
    }

    private String formatHexdump(byte[] bytes, int bytesPerLine) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i += bytesPerLine) {
            // Address
            sb.append(String.format("%08x  ", i));

            // Hex bytes
            for (int j = 0; j < bytesPerLine; j++) {
                if (i + j < bytes.length) {
                    sb.append(String.format("%02x ", bytes[i + j]));
                } else {
                    sb.append("   ");
                }
                if (j == 7) sb.append(" ");
            }

            sb.append(" |");

            // ASCII
            for (int j = 0; j < bytesPerLine && i + j < bytes.length; j++) {
                byte b = bytes[i + j];
                if (b >= 32 && b < 127) {
                    sb.append((char) b);
                } else {
                    sb.append('.');
                }
            }

            sb.append("|\n");
        }
        return sb.toString();
    }

    private JsonObject handleRenameSymbol(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String newName = getString(params, "newName", null);
        String type = getString(params, "type", "function");
        String description = getString(params, "description", null);

        if (address == null || newName == null) {
            throw new IllegalArgumentException("address and newName are required");
        }

        engine.renameSymbol(address, newName, type, description);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("newName", newName);
        return result;
    }

    private JsonObject handleSetComment(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String comment = getString(params, "comment", null);
        String type = getString(params, "type", "EOL");

        if (address == null || comment == null) {
            throw new IllegalArgumentException("address and comment are required");
        }

        engine.setComment(address, comment, type);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleSearch(JsonObject params) throws Exception {
        String filter = getString(params, "filter", null);
        String regex = getString(params, "regex", null);
        String hexPattern = getString(params, "hexPattern", null);
        log.debug("search: filter=" + filter + " regex=" + regex + " hexPattern=" + hexPattern);
        // Backward compat: if old 'pattern' field is present and no filter/regex set, use it as regex
        String oldPattern = getString(params, "pattern", null);
        if (oldPattern != null && filter == null && regex == null && hexPattern == null) {
            regex = oldPattern;
        }
        List<String> types = parseSearchTypes(params);
        boolean caseSensitive = getBoolean(params, "caseSensitive", false);
        int limit = getInt(params, "limit", 100);
        int offset = getInt(params, "offset", 0);
        boolean countOnly = getBoolean(params, "countOnly", false);
        boolean includeContext = getBoolean(params, "includeContext", true);
        String functionFilter = getString(params, "functionFilter", null);
        String searchMode = getString(params, "searchMode", null);
        String flowType = getString(params, "flowType", null);

        // Parse scope
        String scopeType = null, scopeValue = null, scopeStartAddress = null, scopeEndAddress = null;
        if (params.has("scope") && !params.get("scope").isJsonNull()) {
            JsonObject scope = params.getAsJsonObject("scope");
            scopeType = getString(scope, "type", null);
            scopeValue = getString(scope, "value", null);
            scopeStartAddress = getString(scope, "startAddress", null);
            scopeEndAddress = getString(scope, "endAddress", null);
        }

        int maxFunctions = getInt(params, "maxFunctions", 0);

        GhidraEngine.SearchResponse response = engine.search(
            filter, regex, hexPattern, types, caseSensitive, limit, offset, countOnly, includeContext,
            scopeType, scopeValue, scopeStartAddress, scopeEndAddress, functionFilter,
            searchMode, flowType, maxFunctions
        );

        JsonObject result = new JsonObject();
        if (!countOnly) {
            result.add("results", gson.toJsonTree(response.results));
        }
        result.addProperty("total", response.total);
        result.addProperty("offset", offset);
        result.addProperty("limit", limit);
        result.addProperty("hasMore", response.hasMore);
        result.addProperty("countOnly", countOnly);
        if (response.coverageNote != null) {
            result.addProperty("coverageNote", response.coverageNote);
            result.addProperty("functionsScanned", response.scanned);
            result.addProperty("functionsAvailable", response.scannable);
        }
        return result;
    }

    private JsonObject handleSave() throws Exception {
        engine.save();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleCheckin(JsonObject params) throws Exception {
        String message = getString(params, "message", null);
        String status = engine.commit(message);

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("message", status);
        return result;
    }

    private JsonObject handleCreateStructure(JsonObject params) throws Exception {
        String name = getString(params, "name", null);
        String category = getString(params, "category", null);
        boolean packed = getBoolean(params, "packed", false);
        JsonArray fieldsArray = params.has("fields") ? params.getAsJsonArray("fields") : new JsonArray();

        if (name == null) {
            throw new IllegalArgumentException("name is required");
        }

        List<GhidraEngine.StructField> fields = new ArrayList<>();
        for (int i = 0; i < fieldsArray.size(); i++) {
            JsonObject fieldObj = fieldsArray.get(i).getAsJsonObject();
            GhidraEngine.StructField field = new GhidraEngine.StructField();
            field.name = getString(fieldObj, "name", "field_" + i);
            field.dataType = getString(fieldObj, "dataType", "undefined");
            field.offset = getInt(fieldObj, "offset", -1);
            field.bitOffset = getInt(fieldObj, "bitOffset", -1);
            field.comment = getString(fieldObj, "comment", null);
            fields.add(field);
        }

        GhidraEngine.StructureResult structResult = engine.createStructure(name, category, fields, packed);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("name", structResult.name);
        result.addProperty("category", structResult.category);
        result.addProperty("size", structResult.size);
        return result;
    }

    private JsonObject handleExportTypeArchive(JsonObject params) throws Exception {
        String archivePath = getString(params, "archivePath", null);
        if (archivePath == null) {
            throw new IllegalArgumentException("archivePath is required");
        }

        List<String> categories = null;
        if (params.has("categories") && params.get("categories").isJsonArray()) {
            categories = new ArrayList<>();
            JsonArray arr = params.getAsJsonArray("categories");
            for (int i = 0; i < arr.size(); i++) {
                categories.add(arr.get(i).getAsString());
            }
        }

        Map<String, Object> exportResult = engine.exportTypeArchive(archivePath, categories);

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("archivePath", (String) exportResult.get("archivePath"));
        result.addProperty("exported", (int) exportResult.get("exported"));
        result.addProperty("sizeBytes", (long) exportResult.get("sizeBytes"));
        return result;
    }

    private JsonObject handleImportTypeArchive(JsonObject params) throws Exception {
        String archivePath = getString(params, "archivePath", null);
        if (archivePath == null) {
            throw new IllegalArgumentException("archivePath is required");
        }

        List<String> categories = null;
        if (params.has("categories") && params.get("categories").isJsonArray()) {
            categories = new ArrayList<>();
            JsonArray arr = params.getAsJsonArray("categories");
            for (int i = 0; i < arr.size(); i++) {
                categories.add(arr.get(i).getAsString());
            }
        }

        Map<String, Object> importResult = engine.importTypeArchive(archivePath, categories);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("archivePath", (String) importResult.get("archivePath"));
        result.addProperty("imported", (int) importResult.get("imported"));
        return result;
    }

    private JsonObject handleListSymbols(JsonObject params) {
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 100);
        String filter = getString(params, "filter", null);
        String regex = getString(params, "regex", null);
        String type = getString(params, "type", null);

        List<GhidraEngine.SymbolInfo> symbols = engine.listSymbols(offset, limit, filter, regex, type);

        JsonObject result = new JsonObject();
        result.add("symbols", gson.toJsonTree(symbols));
        result.addProperty("total", symbols.size());
        return result;
    }

    private JsonObject handleGetDisassembly(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        int count = getInt(params, "count", 20);
        int context = getInt(params, "context", 0);

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        List<GhidraEngine.DisassemblyLine> lines = engine.getDisassembly(address, count, context);

        JsonObject result = new JsonObject();
        result.add("instructions", gson.toJsonTree(lines));
        result.addProperty("count", lines.size());
        return result;
    }

    private JsonObject handleGetFunctionSummary(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);
        boolean includeStrings = getBoolean(params, "includeStrings", true);
        boolean includeXrefs = getBoolean(params, "includeXrefs", true);
        int maxCalls = getInt(params, "maxCalls", 20);
        int maxCallers = getInt(params, "maxCallers", 20);

        GhidraEngine.FunctionSummary summary = engine.getFunctionSummary(address, name, includeStrings, includeXrefs, maxCalls, maxCallers);

        return gson.toJsonTree(summary).getAsJsonObject();
    }

    private JsonObject handleListDataTypes(JsonObject params) {
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 100);
        String filter = getString(params, "filter", null);
        String regex = getString(params, "regex", null);
        String category = getString(params, "category", null);

        GhidraEngine.ListDataTypesResult listResult = engine.listDataTypes(offset, limit, filter, regex, category);

        JsonObject result = new JsonObject();
        result.add("dataTypes", gson.toJsonTree(listResult.dataTypes));
        result.addProperty("total", listResult.total);
        return result;
    }

    private JsonObject handleGetDataType(JsonObject params) throws Exception {
        String name = getString(params, "name", null);
        String category = getString(params, "category", null);

        if (name == null) {
            throw new IllegalArgumentException("name is required");
        }

        GhidraEngine.DataTypeDetail detail = engine.getDataType(name, category);
        JsonObject result = gson.toJsonTree(detail).getAsJsonObject();

        // For enums, add enumValues as a name->value map for convenient access
        if ("enum".equals(detail.type) && detail.values != null) {
            JsonObject enumValues = new JsonObject();
            for (GhidraEngine.DataTypeDetail.EnumValueDetail ev : detail.values) {
                enumValues.addProperty(ev.name, ev.value);
            }
            result.add("enumValues", enumValues);
        }

        return result;
    }

    private JsonObject handleListComments(JsonObject params) {
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 100);
        String type = getString(params, "type", null);
        String inFunction = getString(params, "inFunction", null);

        List<GhidraEngine.CommentInfo> comments = engine.listComments(offset, limit, type, inFunction);

        JsonObject result = new JsonObject();
        result.add("comments", gson.toJsonTree(comments));
        result.addProperty("total", comments.size());
        return result;
    }

    private JsonObject handleListBookmarks(JsonObject params) {
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 100);
        String type = getString(params, "type", null);
        String category = getString(params, "category", null);

        List<GhidraEngine.BookmarkInfo> bookmarks = engine.listBookmarks(offset, limit, type, category);

        JsonObject result = new JsonObject();
        result.add("bookmarks", gson.toJsonTree(bookmarks));
        result.addProperty("total", bookmarks.size());
        return result;
    }

    private JsonObject handleGetBasicBlocks(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);

        List<GhidraEngine.BasicBlockInfo> blocks = engine.getBasicBlocks(address, name);

        JsonObject result = new JsonObject();
        result.add("blocks", gson.toJsonTree(blocks));
        result.addProperty("total", blocks.size());
        return result;
    }

    private JsonObject handleGetCallGraph(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);
        int depth = getInt(params, "depth", 2);
        String direction = getString(params, "direction", "both");
        int maxNodes = getInt(params, "maxNodes", 500);

        GhidraEngine.CallGraphResult graph = engine.getCallGraph(address, name, depth, direction, maxNodes);

        return gson.toJsonTree(graph).getAsJsonObject();
    }

    private JsonObject handleFindCallPath(JsonObject params) throws Exception {
        String from = getString(params, "from", null);
        String to = getString(params, "to", null);
        int maxDepth = getInt(params, "maxDepth", 10);

        if (from == null || to == null) {
            throw new IllegalArgumentException("from and to are required");
        }

        GhidraEngine.CallPathResult path = engine.findCallPath(from, to, maxDepth);

        return gson.toJsonTree(path).getAsJsonObject();
    }

    private JsonObject handleGetXrefsWithContext(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String direction = getString(params, "direction", "both");
        int contextLines = getInt(params, "contextLines", 5);
        String contextPattern = getString(params, "contextPattern", null);
        int limit = getInt(params, "limit", 50);
        List<String> refTypes = parseStringOrArray(params, "refType");

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        List<GhidraEngine.XRefWithContext> xrefs = engine.getXrefsWithContext(address, direction, contextLines, contextPattern, limit, refTypes);

        JsonObject result = new JsonObject();
        result.add("xrefs", gson.toJsonTree(xrefs));
        result.addProperty("total", xrefs.size());
        return result;
    }

    private JsonObject handleGetClassInfo(JsonObject params) throws Exception {
        String name = getString(params, "name", null);

        if (name == null) {
            throw new IllegalArgumentException("name is required");
        }

        GhidraEngine.ClassInfo classInfo = engine.getClassInfo(name);
        return gson.toJsonTree(classInfo).getAsJsonObject();
    }

    private JsonObject handleGetPcode(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);
        boolean highLevel = getBoolean(params, "highLevel", false);

        GhidraEngine.PcodeResult pcode = engine.getPcode(address, name, highLevel);

        return gson.toJsonTree(pcode).getAsJsonObject();
    }

    private JsonObject handleBatchPcode(JsonObject params) {
        boolean highLevel = getBoolean(params, "highLevel", false);
        JsonArray addressArray = params.has("addresses") ? params.getAsJsonArray("addresses") : new JsonArray();

        JsonArray results = new JsonArray();
        for (int i = 0; i < addressArray.size(); i++) {
            String addr = addressArray.get(i).getAsString();
            JsonObject entry = new JsonObject();
            entry.addProperty("address", addr);
            try {
                GhidraEngine.PcodeResult pcode = engine.getPcode(addr, null, highLevel);
                entry.addProperty("functionName", pcode.functionName);
                entry.add("pcode", gson.toJsonTree(pcode));
            } catch (Exception e) {
                entry.addProperty("functionName", "");
                entry.addProperty("error", e.getMessage());
            }
            results.add(entry);
        }

        JsonObject result = new JsonObject();
        result.add("results", results);
        return result;
    }

    private JsonObject handleSetDataType(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String dataType = getString(params, "dataType", null);
        int length = getInt(params, "length", -1);

        if (address == null || dataType == null) {
            throw new IllegalArgumentException("address and dataType are required");
        }

        engine.setDataType(address, dataType, length);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleSetPrototype(JsonObject params) throws Exception {
        String functionAddress = getString(params, "functionAddress", null);
        String prototype = getString(params, "prototype", null);
        String description = getString(params, "description", null);
        boolean force = params.has("force") && !params.get("force").isJsonNull()
            && params.get("force").getAsBoolean();

        if (functionAddress == null || prototype == null) {
            throw new IllegalArgumentException("functionAddress and prototype are required");
        }

        String callingConvention = getString(params, "callingConvention", null);

        java.util.List<String> warnings = engine.setPrototype(
            functionAddress, prototype, description, callingConvention, force);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        if (warnings != null && !warnings.isEmpty()) {
            result.add("warnings", gson.toJsonTree(warnings));
        }
        return result;
    }

    private JsonObject handleSetCustomSignature(JsonObject params) throws Exception {
        String functionAddress = getString(params, "functionAddress", null);
        String returnType = getString(params, "returnType", "void");
        String description = getString(params, "description", null);
        boolean force = params.has("force") && !params.get("force").isJsonNull()
            && params.get("force").getAsBoolean();
        JsonArray parametersArray = params.has("parameters") ? params.getAsJsonArray("parameters") : new JsonArray();

        if (functionAddress == null) {
            throw new IllegalArgumentException("functionAddress is required");
        }

        List<GhidraEngine.CustomParameter> parameters = new ArrayList<>();
        for (int i = 0; i < parametersArray.size(); i++) {
            JsonObject paramObj = parametersArray.get(i).getAsJsonObject();
            GhidraEngine.CustomParameter param = new GhidraEngine.CustomParameter();
            param.name = getString(paramObj, "name", "param_" + i);
            param.dataType = getString(paramObj, "dataType", "int");
            param.storage = getString(paramObj, "storage", null);
            if (param.storage == null) {
                throw new IllegalArgumentException("storage is required for parameter: " + param.name);
            }
            parameters.add(param);
        }

        engine.setCustomSignature(functionAddress, returnType, parameters, description, force);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleBatchRename(JsonObject params) throws Exception {
        JsonArray mappingsArray = params.has("mappings") ? params.getAsJsonArray("mappings") : new JsonArray();
        boolean dryRun = getBoolean(params, "dryRun", false);
        String description = getString(params, "description", null);

        List<GhidraEngine.RenameMapping> mappings = new ArrayList<>();
        for (int i = 0; i < mappingsArray.size(); i++) {
            JsonObject mapObj = mappingsArray.get(i).getAsJsonObject();
            GhidraEngine.RenameMapping mapping = new GhidraEngine.RenameMapping();
            mapping.address = getString(mapObj, "address", null);
            mapping.newName = getString(mapObj, "newName", null);
            mappings.add(mapping);
        }

        GhidraEngine.BatchRenameResult renameResult = engine.batchRename(mappings, dryRun, description);
        if (!dryRun) {
            engine.invalidateCache();
        }

        return gson.toJsonTree(renameResult).getAsJsonObject();
    }

    private JsonObject handleFindFunctionsMatching(JsonObject params) {
        JsonArray callsArray = params.has("calls") ? params.getAsJsonArray("calls") : null;
        JsonArray notCallsArray = params.has("notCalls") ? params.getAsJsonArray("notCalls") : null;
        String referencesString = getString(params, "referencesString", null);
        String inNamespace = getString(params, "inNamespace", null);
        int sizeMin = getInt(params, "sizeMin", -1);
        int sizeMax = getInt(params, "sizeMax", -1);
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 50);
        log.debug("find_functions_matching: ns=" + inNamespace + " refStr=" + referencesString +
            " calls=" + (callsArray != null ? callsArray.size() : 0) + " limit=" + limit);

        List<String> calls = new ArrayList<>();
        List<String> notCalls = new ArrayList<>();

        if (callsArray != null) {
            for (int i = 0; i < callsArray.size(); i++) {
                calls.add(callsArray.get(i).getAsString());
            }
        }
        if (notCallsArray != null) {
            for (int i = 0; i < notCallsArray.size(); i++) {
                notCalls.add(notCallsArray.get(i).getAsString());
            }
        }

        GhidraEngine.FindFunctionsResult found = engine.findFunctionsMatching(
            calls, notCalls, referencesString, inNamespace, sizeMin, sizeMax, offset, limit);

        JsonObject result = new JsonObject();
        result.add("functions", gson.toJsonTree(found.functions));
        result.addProperty("total", found.total);
        result.addProperty("offset", found.offset);
        result.addProperty("limit", found.limit);
        result.addProperty("hasMore", found.hasMore);
        return result;
    }

    private JsonObject handleTraceDataFlow(JsonObject params) throws Exception {
        String from = getString(params, "from", null);
        int depth = getInt(params, "depth", 5);
        boolean includeCalls = getBoolean(params, "includeCalls", true);

        if (from == null) {
            throw new IllegalArgumentException("from is required");
        }

        GhidraEngine.DataFlowResult flow = engine.traceDataFlow(from, depth, includeCalls);

        return gson.toJsonTree(flow).getAsJsonObject();
    }

    private JsonObject handleGetAnalysisHints(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String function = getString(params, "function", null);

        GhidraEngine.AnalysisHints hints = engine.getAnalysisHints(address, function);

        return gson.toJsonTree(hints).getAsJsonObject();
    }

    private JsonObject handleExecuteScript(JsonObject params) throws Exception {
        String code = getString(params, "code", null);
        String filePath = getString(params, "filePath", null);
        String language = getString(params, "language", "python");
        int timeout = getInt(params, "timeout", 30);
        boolean sandbox = getBoolean(params, "sandbox", true);

        if (code == null && filePath == null) {
            throw new IllegalArgumentException("code or filePath is required");
        }

        // Auto-detect language from file extension
        if (filePath != null && language.equals("python") && filePath.endsWith(".js")) {
            language = "javascript";
        }
        if (filePath != null && language.equals("python") && filePath.endsWith(".java")) {
            language = "java";
        }

        GhidraEngine.ScriptResult scriptResult;
        if (language.equals("python")) {
            scriptResult = engine.executePythonScript(code, filePath, timeout, sandbox);
        } else if (language.equals("java")) {
            // Java GhidraScript path — read file if needed
            if (code == null && filePath != null) {
                code = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath)));
            }
            scriptResult = engine.executeJavaScript(code, timeout, sandbox);
        } else {
            // JavaScript path — read file if needed
            if (code == null && filePath != null) {
                code = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath)));
            }
            scriptResult = engine.executeScript(code, timeout, sandbox);
        }

        return gson.toJsonTree(scriptResult).getAsJsonObject();
    }

    private JsonObject handleGetLineMappings(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);
        int timeout = getInt(params, "timeout", 30);

        if (address == null && name == null) {
            throw new IllegalArgumentException("address or name is required");
        }

        List<GhidraEngine.LineMapping> mappings = engine.getLineMappings(address, name, timeout);

        JsonObject result = new JsonObject();
        result.add("mappings", gson.toJsonTree(mappings));
        result.addProperty("total", mappings.size());
        return result;
    }

    private JsonObject handleGetGlobalVariables(JsonObject params) {
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 100);
        String filter = getString(params, "filter", null);
        String regex = getString(params, "regex", null);
        String segment = getString(params, "segment", null);
        String sortBy = getString(params, "sortBy", null);
        String dataType = getString(params, "dataType", null);

        GhidraEngine.GlobalVariablesResult globalsResult = engine.getGlobalVariablesWithTotal(offset, limit, filter, regex, segment, sortBy, dataType);

        JsonObject result = new JsonObject();
        result.add("globals", gson.toJsonTree(globalsResult.globals));
        result.addProperty("total", globalsResult.total);
        return result;
    }

    private JsonObject handleReadDataValue(JsonObject params) {
        String address = getString(params, "address", null);
        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        GhidraEngine.DataValueResult dataValue = engine.readDataValue(address);

        JsonObject result = new JsonObject();
        if (dataValue != null) {
            result.add("value", gson.toJsonTree(dataValue));
        } else {
            result.addProperty("error", "No defined data at address " + address);
        }
        return result;
    }

    // ==================== NEW HANDLERS ====================

    private JsonObject handleAddBookmark(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String category = getString(params, "category", "Analysis");
        String comment = getString(params, "comment", "");
        String type = getString(params, "type", "Note");

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        engine.addBookmark(address, type, category, comment);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleDeleteBookmark(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String type = getString(params, "type", null);

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        engine.deleteBookmark(address, type);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleDeleteComment(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String type = getString(params, "type", "EOL");

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        engine.deleteComment(address, type);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleCreateLabel(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);
        String namespace = getString(params, "namespace", null);
        boolean primary = getBoolean(params, "primary", true);

        if (address == null || name == null) {
            throw new IllegalArgumentException("address and name are required");
        }

        engine.createLabel(address, name, namespace, primary);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleDeleteLabel(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        engine.deleteLabel(address, name);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleCreateFunction(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        GhidraEngine.FunctionInfo info = engine.createFunction(address, name);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.add("function", gson.toJsonTree(info));
        return result;
    }

    private JsonObject handleDeleteFunction(JsonObject params) throws Exception {
        String address = getString(params, "address", null);

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        engine.deleteFunction(address);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleCreateEnum(JsonObject params) throws Exception {
        String name = getString(params, "name", null);
        String category = getString(params, "category", null);
        int size = getInt(params, "size", 4);

        if (name == null || !params.has("values")) {
            throw new IllegalArgumentException("name and values are required");
        }

        JsonObject valuesObj = params.getAsJsonObject("values");
        java.util.Map<String, Long> values = new java.util.HashMap<>();
        for (String key : valuesObj.keySet()) {
            values.put(key, valuesObj.get(key).getAsLong());
        }

        GhidraEngine.DataTypeResult dtResult = engine.createEnum(name, values, category, size);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("name", dtResult.name);
        result.addProperty("category", dtResult.category);
        result.addProperty("size", dtResult.size);
        return result;
    }

    private JsonObject handleCreateUnion(JsonObject params) throws Exception {
        String name = getString(params, "name", null);
        String category = getString(params, "category", null);
        JsonArray fieldsArray = params.has("fields") ? params.getAsJsonArray("fields") : new JsonArray();

        if (name == null) {
            throw new IllegalArgumentException("name is required");
        }

        List<GhidraEngine.StructField> fields = new ArrayList<>();
        for (int i = 0; i < fieldsArray.size(); i++) {
            JsonObject fieldObj = fieldsArray.get(i).getAsJsonObject();
            GhidraEngine.StructField field = new GhidraEngine.StructField();
            field.name = getString(fieldObj, "name", "field_" + i);
            field.dataType = getString(fieldObj, "dataType", "undefined");
            field.comment = getString(fieldObj, "comment", null);
            fields.add(field);
        }

        GhidraEngine.DataTypeResult dtResult = engine.createUnion(name, fields, category);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("name", dtResult.name);
        result.addProperty("category", dtResult.category);
        result.addProperty("size", dtResult.size);
        return result;
    }

    private JsonObject handleCreateTypedef(JsonObject params) throws Exception {
        String name = getString(params, "name", null);
        String baseType = getString(params, "baseType", null);
        String category = getString(params, "category", null);

        if (name == null || baseType == null) {
            throw new IllegalArgumentException("name and baseType are required");
        }

        GhidraEngine.DataTypeResult dtResult = engine.createTypedef(name, baseType, category);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("name", dtResult.name);
        result.addProperty("category", dtResult.category);
        // Report the size so a caller can see what was actually built rather than
        // having to read the type back.
        result.addProperty("size", dtResult.size);
        return result;
    }

    private JsonObject handleCreateFuncdef(JsonObject params) throws Exception {
        String name = getString(params, "name", null);
        String returnType = getString(params, "returnType", "void");
        String callingConvention = getString(params, "callingConvention", null);
        String category = getString(params, "category", null);
        JsonArray paramsArray = params.has("parameters")
            ? params.getAsJsonArray("parameters") : new JsonArray();

        if (name == null) {
            throw new IllegalArgumentException("name is required");
        }

        List<GhidraEngine.FuncdefParam> defs = new ArrayList<>();
        for (int i = 0; i < paramsArray.size(); i++) {
            JsonObject o = paramsArray.get(i).getAsJsonObject();
            GhidraEngine.FuncdefParam p = new GhidraEngine.FuncdefParam();
            p.name = getString(o, "name", "param_" + (i + 1));
            p.dataType = getString(o, "dataType", null);
            p.comment = getString(o, "comment", null);
            if (p.dataType == null) {
                throw new IllegalArgumentException(
                    "parameters[" + i + "].dataType is required");
            }
            defs.add(p);
        }

        GhidraEngine.DataTypeResult dtResult =
            engine.createFuncdef(name, returnType, defs, callingConvention, category);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("name", dtResult.name);
        result.addProperty("category", dtResult.category);
        // Echo the convention the funcdef actually carries, so a caller that
        // omitted one sees "unknown" here instead of discovering it later.
        result.addProperty("callingConvention", dtResult.callingConvention);
        result.addProperty("effectiveCallingConvention", dtResult.effectiveCallingConvention);
        result.addProperty("hasUnknownCallingConvention", dtResult.hasUnknownCallingConvention);
        return result;
    }

    private JsonObject handleUpdateStructure(JsonObject params) throws Exception {
        String name = getString(params, "name", null);
        String category = getString(params, "category", null);
        String operation = getString(params, "operation", "replace");
        JsonArray fieldsArray = params.has("fields") ? params.getAsJsonArray("fields") : null;
        String fieldName = getString(params, "fieldName", null);
        boolean force = getBoolean(params, "force", false);

        if (name == null) {
            throw new IllegalArgumentException("name is required");
        }

        List<GhidraEngine.StructField> fields = null;
        if (fieldsArray != null) {
            fields = new ArrayList<>();
            for (int i = 0; i < fieldsArray.size(); i++) {
                JsonObject fieldObj = fieldsArray.get(i).getAsJsonObject();
                GhidraEngine.StructField field = new GhidraEngine.StructField();
                field.name = getString(fieldObj, "name", null);
                field.dataType = getString(fieldObj, "dataType", null);
                field.offset = getInt(fieldObj, "offset", -1);
                field.bitOffset = getInt(fieldObj, "bitOffset", -1);
                field.comment = getString(fieldObj, "comment", null);
                // updateFields-specific params
                field.fieldName = getString(fieldObj, "fieldName", null);
                field.newName = getString(fieldObj, "newName", null);
                field.newDataType = getString(fieldObj, "newDataType", null);
                // Backward compat: for non-updateFields ops, default name/dataType
                if (field.name == null) field.name = "field_" + i;
                if (field.dataType == null) field.dataType = "undefined";
                fields.add(field);
            }
        }

        GhidraEngine.StructureResult structResult = engine.updateStructure(name, category, operation, fields, fieldName, force);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("name", structResult.name);
        result.addProperty("category", structResult.category);
        result.addProperty("size", structResult.size);
        if (structResult.warning != null) {
            result.addProperty("warning", structResult.warning);
        }
        return result;
    }

    private JsonObject handleDeleteDataType(JsonObject params) throws Exception {
        String name = getString(params, "name", null);
        String category = getString(params, "category", null);

        if (name == null) {
            throw new IllegalArgumentException("name is required");
        }

        engine.deleteDataType(name, category);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleDisassemble(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        int length = getInt(params, "length", -1);

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        int disassembled = engine.disassemble(address, length);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("instructionsCreated", disassembled);
        return result;
    }

    private JsonObject handleClearListing(JsonObject params) throws Exception {
        String startAddress = getString(params, "startAddress", null);
        String endAddress = getString(params, "endAddress", null);

        if (startAddress == null) {
            throw new IllegalArgumentException("startAddress is required");
        }

        engine.clearListing(startAddress, endAddress);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleSetFunctionVariableName(JsonObject params) throws Exception {
        String functionAddress = getString(params, "functionAddress", null);
        String oldName = getString(params, "oldName", null);
        String newName = getString(params, "newName", null);
        String description = getString(params, "description", null);
        boolean force = params.has("force") && !params.get("force").isJsonNull()
            && params.get("force").getAsBoolean();

        if (functionAddress == null || oldName == null || newName == null) {
            throw new IllegalArgumentException("functionAddress, oldName, and newName are required");
        }

        engine.setFunctionVariableName(functionAddress, oldName, newName, description, force);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleSetFunctionVariableType(JsonObject params) throws Exception {
        String functionAddress = getString(params, "functionAddress", null);
        String variableName = getString(params, "variableName", null);
        String dataType = getString(params, "dataType", null);
        String description = getString(params, "description", null);
        // forceRemoveConflicts: default true (existing behaviour — remove overlapping stack vars)
        boolean forceRemoveConflicts = !params.has("force") || params.get("force").isJsonNull() || params.get("force").getAsBoolean();
        // forceGuard: explicit read-guard bypass, defaults false
        boolean forceGuard = params.has("force") && !params.get("force").isJsonNull()
            && params.get("force").getAsBoolean();

        if (functionAddress == null || variableName == null || dataType == null) {
            throw new IllegalArgumentException("functionAddress, variableName, and dataType are required");
        }

        com.ghidramcp.operations.AnalysisOps.VariableTypeChange change =
            engine.setFunctionVariableType(functionAddress, variableName, dataType, description, forceRemoveConflicts, forceGuard);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        // Echo what the name actually resolved to. A name can land on a different type than
        // the caller meant (the builtin 'dword' rather than WinDef.h/DWORD), so say which one
        // was used instead of making the caller read the function back to find out.
        result.addProperty("resolvedType", change.resolvedType);
        if (change.previousType != null) {
            result.addProperty("previousType", change.previousType);
        }
        if (change.sizeChanged) {
            result.addProperty("previousSize", change.previousSize);
            result.addProperty("newSize", change.newSize);
        }
        if (!change.removedVariables.isEmpty()) {
            result.add("removedVariables", gson.toJsonTree(change.removedVariables));
        }
        if (change.warning != null) {
            result.addProperty("warning", change.warning);
        }
        return result;
    }

    // ==================== EQUATE HANDLERS ====================

    private JsonObject handleListEquates(JsonObject params) {
        int offset = getInt(params, "offset", 0);
        int limit = getInt(params, "limit", 100);
        String filter = getString(params, "filter", null);
        String regex = getString(params, "regex", null);
        Long value = null;
        if (params.has("value") && !params.get("value").isJsonNull()) {
            value = params.get("value").getAsLong();
        }

        GhidraEngine.ListEquatesResult listResult = engine.listEquates(offset, limit, filter, regex, value);

        JsonObject result = new JsonObject();
        result.add("equates", gson.toJsonTree(listResult.equates));
        result.addProperty("total", listResult.total);
        return result;
    }

    private JsonObject handleSetEquate(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        int operandIndex = getInt(params, "operandIndex", 0);
        String name = getString(params, "name", null);

        if (address == null || name == null || !params.has("value")) {
            throw new IllegalArgumentException("address, value, and name are required");
        }

        long value = params.get("value").getAsLong();
        engine.setEquate(address, operandIndex, value, name);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    private JsonObject handleDeleteEquate(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        int operandIndex = getInt(params, "operandIndex", 0);
        String name = getString(params, "name", null);

        if (address == null || name == null) {
            throw new IllegalArgumentException("address and name are required");
        }

        engine.deleteEquate(address, operandIndex, name);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        return result;
    }

    /**
     * Parse a JSON value that can be either a string or array of strings.
     * Returns null if the key is missing or null.
     */
    private List<String> parseStringOrArray(JsonObject params, String key) {
        if (!params.has(key) || params.get(key).isJsonNull()) {
            return null;
        }
        List<String> list = new ArrayList<>();
        if (params.get(key).isJsonArray()) {
            JsonArray arr = params.getAsJsonArray(key);
            for (int i = 0; i < arr.size(); i++) {
                list.add(arr.get(i).getAsString());
            }
        } else {
            list.add(params.get(key).getAsString());
        }
        return list;
    }

    private List<String> parseSearchTypes(JsonObject params) {
        List<String> types = new ArrayList<>();

        if (!params.has("type") || params.get("type").isJsonNull()) {
            types.add("all");
            return types;
        }

        // Handle both string and array of strings
        if (params.get("type").isJsonArray()) {
            JsonArray arr = params.getAsJsonArray("type");
            for (int i = 0; i < arr.size(); i++) {
                types.add(arr.get(i).getAsString());
            }
        } else {
            types.add(params.get("type").getAsString());
        }

        return types;
    }

    // Helper methods
    private String getString(JsonObject obj, String key, String defaultValue) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return defaultValue;
    }

    private int getInt(JsonObject obj, String key, int defaultValue) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsInt();
        }
        return defaultValue;
    }

    private boolean getBoolean(JsonObject obj, String key, boolean defaultValue) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsBoolean();
        }
        return defaultValue;
    }

    // ==================== FUNCTION ATTRIBUTES/TAGS ====================

    private JsonObject handleSetFunctionAttributes(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);
        String callingConvention = getString(params, "callingConvention", null);
        Boolean noReturn = params.has("noReturn") && !params.get("noReturn").isJsonNull()
            ? params.get("noReturn").getAsBoolean() : null;
        Boolean inline = params.has("inline") && !params.get("inline").isJsonNull()
            ? params.get("inline").getAsBoolean() : null;
        Boolean varArgs = params.has("varArgs") && !params.get("varArgs").isJsonNull()
            ? params.get("varArgs").getAsBoolean() : null;
        boolean force = params.has("force") && !params.get("force").isJsonNull()
            && params.get("force").getAsBoolean();

        GhidraEngine.FunctionAttributesResult result = engine.setFunctionAttributes(
            address, name, callingConvention, noReturn, inline, varArgs, force);
        engine.invalidateCache();

        return gson.toJsonTree(result).getAsJsonObject();
    }

    private JsonObject handleAddFunctionTag(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);
        String tag = getString(params, "tag", null);

        if (tag == null) {
            throw new IllegalArgumentException("tag is required");
        }

        List<String> tags = engine.addFunctionTag(address, name, tag);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.add("tags", gson.toJsonTree(tags));
        return result;
    }

    private JsonObject handleRemoveFunctionTag(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);
        String tag = getString(params, "tag", null);

        if (tag == null) {
            throw new IllegalArgumentException("tag is required");
        }

        List<String> tags = engine.removeFunctionTag(address, name, tag);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.add("tags", gson.toJsonTree(tags));
        return result;
    }

    private JsonObject handleBatchTagSymbols(JsonObject params) throws Exception {
        JsonArray operations = params.getAsJsonArray("operations");

        if (operations == null || operations.size() == 0) {
            throw new IllegalArgumentException("operations array is required");
        }

        GhidraEngine.BatchTagResult batchResult = engine.batchTagSymbols(operations);
        engine.invalidateCache();

        return gson.toJsonTree(batchResult).getAsJsonObject();
    }

    // ==================== NAMESPACE MANAGEMENT ====================

    private JsonObject handleCreateNamespace(JsonObject params) throws Exception {
        String name = getString(params, "name", null);
        String parent = getString(params, "parent", null);
        boolean isClass = getBoolean(params, "isClass", false);

        if (name == null) {
            throw new IllegalArgumentException("name is required");
        }

        GhidraEngine.NamespaceResult nsResult = engine.createNamespace(name, parent, isClass);
        engine.invalidateCache();

        return gson.toJsonTree(nsResult).getAsJsonObject();
    }

    private JsonObject handleMoveSymbolToNamespace(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String namespace = getString(params, "namespace", null);
        String type = getString(params, "type", "function");

        if (address == null || namespace == null) {
            throw new IllegalArgumentException("address and namespace are required");
        }

        GhidraEngine.MoveSymbolResult moveResult = engine.moveSymbolToNamespace(address, namespace, type);
        engine.invalidateCache();

        return gson.toJsonTree(moveResult).getAsJsonObject();
    }

    private JsonObject handleRenameNamespace(JsonObject params) throws Exception {
        String oldName = getString(params, "oldName", null);
        String newName = getString(params, "newName", null);

        if (oldName == null || newName == null) {
            throw new IllegalArgumentException("oldName and newName are required");
        }

        engine.renameNamespace(oldName, newName);
        engine.invalidateCache();

        JsonObject result = new JsonObject();
        result.addProperty("oldName", oldName);
        result.addProperty("newName", newName);
        return result;
    }

    private JsonObject handleDeleteNamespace(JsonObject params) throws Exception {
        String name = getString(params, "name", null);
        if (name == null) {
            throw new IllegalArgumentException("name is required");
        }
        boolean force = params.has("force") && !params.get("force").isJsonNull()
            && params.get("force").getAsBoolean();

        GhidraEngine.DeleteNamespaceResult result = engine.deleteNamespace(name, force);
        engine.invalidateCache();

        return gson.toJsonTree(result).getAsJsonObject();
    }

    // ==================== UNDO/REDO ====================

    private JsonObject handleUndo() throws Exception {
        GhidraEngine.UndoRedoResult undoResult = engine.undo();
        return gson.toJsonTree(undoResult).getAsJsonObject();
    }

    private JsonObject handleRedo() throws Exception {
        GhidraEngine.UndoRedoResult redoResult = engine.redo();
        return gson.toJsonTree(redoResult).getAsJsonObject();
    }

    private JsonObject handleGetUndoHistory() {
        GhidraEngine.UndoHistoryResult history = engine.getUndoHistory();
        return gson.toJsonTree(history).getAsJsonObject();
    }

    // ==================== ANALYSIS ====================

    private JsonObject handleGetStackFrame(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        String name = getString(params, "name", null);

        GhidraEngine.StackFrameResult stackResult = engine.getStackFrame(address, name);
        return gson.toJsonTree(stackResult).getAsJsonObject();
    }

    private JsonObject handleReanalyze(JsonObject params) throws Exception {
        String address = getString(params, "address", null);

        GhidraEngine.ReanalyzeResult result = engine.reanalyze(address);
        engine.invalidateCache();

        return gson.toJsonTree(result).getAsJsonObject();
    }

    // ==================== SWITCH TABLE ====================

    private JsonObject handleGetSwitchTable(JsonObject params) throws Exception {
        String address = getString(params, "address", null);

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        GhidraEngine.SwitchTableResult switchResult = engine.getSwitchTable(address);
        return gson.toJsonTree(switchResult).getAsJsonObject();
    }

    private JsonObject handleSetSwitchOverride(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        com.google.gson.JsonArray casesArray = params.has("caseAddresses") ? params.getAsJsonArray("caseAddresses") : null;
        if (casesArray == null || casesArray.size() == 0) {
            throw new IllegalArgumentException("caseAddresses is required and must be non-empty");
        }

        java.util.List<String> caseAddresses = new java.util.ArrayList<>();
        for (int i = 0; i < casesArray.size(); i++) {
            caseAddresses.add(casesArray.get(i).getAsString());
        }

        GhidraEngine.SwitchOverrideResult result = engine.setSwitchOverride(address, caseAddresses);
        return gson.toJsonTree(result).getAsJsonObject();
    }

    // ==================== EXPORT ALL C ====================

    private JsonObject handleExportAllC(JsonObject params) {
        // decompileTimeout is per-function timeout in seconds (default 30)
        // 'timeout' in params is for the worker pool, we use decompileTimeout for decompilation
        int decompileTimeout = getInt(params, "decompileTimeout", 30);
        boolean includeTypes = getBoolean(params, "includeTypes", true);
        boolean includeHeaders = getBoolean(params, "includeHeaders", true);

        GhidraEngine.ExportAllCResult result = engine.exportAllC(decompileTimeout, includeTypes, includeHeaders);

        return gson.toJsonTree(result).getAsJsonObject();
    }

    private JsonObject handleGetCacheVersion() {
        JsonObject result = new JsonObject();
        result.addProperty("cacheVersion", engine.getCacheVersion());
        return result;
    }

    // ==================== MULTI-PROGRAM ====================

    private JsonObject handleListPrograms(JsonObject params) throws Exception {
        // List straight off the server whenever this worker has no project of its own to
        // list — that is what makes the server discoverable before anything is open. With
        // no repo named, every repository is listed.
        String repo = getString(params, "repo", null);
        if (repo != null || !engine.hasOpenProject()) {
            return engine.repo().listRepoPrograms(repo,
                    getString(params, "folder", null),
                    getBoolean(params, "recursive", true),
                    getString(params, "filter", null));
        }
        JsonArray programs = engine.listPrograms();
        JsonObject result = new JsonObject();
        result.add("programs", programs);
        return result;
    }

    private JsonObject handleLoadProgram(JsonObject params) throws Exception {
        String programPath = getString(params, "programPath", null);
        if (programPath == null) {
            throw new IllegalArgumentException("programPath is required");
        }
        // Server-backed worker: load from the already-open repository project (no .gpr lock).
        if (engine.isServerMode()) {
            engine.loadServerProgram(programPath);
        } else {
            engine.loadAdditionalProgram(programPath);
        }
        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("programPath", programPath);
        return result;
    }

    // ==================== VERSION TRACKING ====================

    private JsonObject handleVtCreateSession(JsonObject params) throws Exception {
        String sourcePath = getString(params, "sourceProgramPath", null);
        String destPath = getString(params, "destProgramPath", null);
        if (sourcePath == null || destPath == null) {
            throw new IllegalArgumentException("sourceProgramPath and destProgramPath are required");
        }
        return engine.vtCreateSession(sourcePath, destPath);
    }

    private JsonObject handleVtRunCorrelator(JsonObject params) throws Exception {
        String correlatorName = getString(params, "correlatorName", null);
        if (correlatorName == null) {
            throw new IllegalArgumentException("correlatorName is required");
        }
        return engine.vtRunCorrelator(correlatorName);
    }

    private JsonObject handleVtListMatches(JsonObject params) throws Exception {
        double minScore = params.has("minScore") && !params.get("minScore").isJsonNull()
            ? params.get("minScore").getAsDouble() : 0.0;
        int limit = getInt(params, "limit", 100);
        return engine.vtListMatches(minScore, limit);
    }

    private JsonObject handleVtAcceptMatches(JsonObject params) throws Exception {
        boolean acceptAll = getBoolean(params, "acceptAll", false);
        double minScore = params.has("minScore") && !params.get("minScore").isJsonNull()
            ? params.get("minScore").getAsDouble() : 0.0;
        return engine.vtAcceptMatches(acceptAll, minScore);
    }

    private JsonObject handleVtApplyMarkup() throws Exception {
        return engine.vtApplyMarkup();
    }

    private JsonObject handleVtGetCorrelators() {
        return engine.vtGetCorrelators();
    }

    private JsonObject handleGetDataAtAddress(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        int lookAhead = getInt(params, "lookAhead", 0);

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        java.util.Map<String, Object> data = engine.getDataAtAddress(address, lookAhead);
        return gson.toJsonTree(data).getAsJsonObject();
    }

    private JsonObject handleGetSymbolAfter(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        int count = getInt(params, "count", 10);

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        java.util.List<java.util.Map<String, Object>> symbols = engine.getSymbolsAfter(address, count);
        JsonObject result = new JsonObject();
        result.add("symbols", gson.toJsonTree(symbols));
        result.addProperty("total", symbols.size());
        return result;
    }

    private JsonObject handleDetectTable(JsonObject params) throws Exception {
        String address = getString(params, "address", null);
        int maxEntries = getInt(params, "maxEntries", 256);
        boolean applyType = getBoolean(params, "applyType", false);
        String name = getString(params, "name", null);

        if (address == null) {
            throw new IllegalArgumentException("address is required");
        }

        java.util.Map<String, Object> tableResult = engine.detectTable(address, maxEntries, applyType, name);
        if (applyType) {
            engine.invalidateCache();
        }
        return gson.toJsonTree(tableResult).getAsJsonObject();
    }

    // ============== Dirty Tracking ==============

    private JsonObject handleGetDirtySymbols() {
        DirtyTracker tracker = engine.getContext().getDirtyTracker();
        if (tracker == null) {
            JsonObject result = new JsonObject();
            result.add("functions", new com.google.gson.JsonArray());
            result.add("dataTypes", new com.google.gson.JsonArray());
            result.add("globals", new com.google.gson.JsonArray());
            result.addProperty("lastCleanVersion", 0);
            return result;
        }
        return tracker.getDetailJson();
    }

    private JsonObject handleMarkClean() {
        DirtyTracker tracker = engine.getContext().getDirtyTracker();
        if (tracker == null) {
            JsonObject result = new JsonObject();
            result.addProperty("version", 0);
            return result;
        }
        tracker.markClean();
        JsonObject result = new JsonObject();
        result.addProperty("version", engine.getProgram().getModificationNumber());
        return result;
    }
}
