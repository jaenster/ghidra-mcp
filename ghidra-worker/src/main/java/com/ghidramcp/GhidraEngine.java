package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import com.ghidramcp.operations.*;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.*;
import ghidra.util.task.ConsoleTaskMonitor;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.File;
import java.util.*;

/**
 * Thin facade over Ghidra's analysis engine for headless operation.
 * Delegates all work to six operation classes; retains all static DTO
 * inner classes so that CommandHandler references (GhidraEngine.FunctionInfo, etc.)
 * continue to compile unchanged.
 */
public class GhidraEngine {

    private final GhidraContext ctx;
    private final ProjectOps projectOps;
    private final FunctionOps functionOps;
    private final SymbolOps symbolOps;
    private final DataTypeOps dataTypeOps;
    private final MemoryOps memoryOps;
    private final AnalysisOps analysisOps;
    private final VersionTrackingOps vtOps;

    public GhidraEngine(String projectPath, Logger log) throws Exception {
        this.ctx = new GhidraContext(projectPath, log, new ConsoleTaskMonitor());
        ProjectOps.initializeGhidra();
        this.projectOps = new ProjectOps(ctx);
        this.functionOps = new FunctionOps(ctx);
        this.symbolOps = new SymbolOps(ctx);
        this.dataTypeOps = new DataTypeOps(ctx);
        this.memoryOps = new MemoryOps(ctx);
        this.analysisOps = new AnalysisOps(ctx);
        this.vtOps = new VersionTrackingOps(ctx);
    }

    // ============== Direct context accessors ==============

    public GhidraContext getContext() { return ctx; }
    public Program getProgram() { return ctx.getProgram(); }
    public FlatProgramAPI getFlatApi() { return ctx.getFlatApi(); }
    public long getCacheVersion() { return ctx.getCacheVersion(); }
    public void invalidateCache() { ctx.invalidateCache(); }

    // ============== ProjectOps (7 methods) ==============

    public void loadProgram(File binaryFile, boolean analyze, int analysisTimeout) throws Exception {
        projectOps.loadProgram(binaryFile, analyze, analysisTimeout);
    }

    public void openProject(File gprFile) throws Exception {
        projectOps.openProject(gprFile);
    }

    public void openProject(File gprFile, String programPath) throws Exception {
        projectOps.openProject(gprFile, programPath);
    }

    public void openProjectReadOnly(File gprFile) throws Exception {
        projectOps.openProjectReadOnly(gprFile);
    }

    public void openProjectReadOnly(File gprFile, String programPath) throws Exception {
        projectOps.openProjectReadOnly(gprFile, programPath);
    }

    public void loadAdditionalProgram(String programPath) throws Exception {
        projectOps.loadAdditionalProgram(programPath);
    }

    /** Load an additional program from the already-open Ghidra Server project. */
    public void loadServerProgram(String programPath) throws Exception {
        projectOps.loadServerProgram(programPath);
    }

    /** True when this worker holds an open Ghidra Server project. */
    public boolean isServerMode() {
        return projectOps.isServerMode();
    }

    /**
     * Connect to a remote Ghidra Server and open a shared program from a repository.
     * Opens read-only by default to avoid locking/writing the production repository.
     */
    public void openServerProgram(String host, int port, String repo, String programPath,
                                  String user, char[] password, boolean readOnly) throws Exception {
        projectOps.openServerProgram(host, port, repo, programPath, user, password, readOnly);
    }

    public JsonArray listPrograms() throws Exception {
        return projectOps.listProjectPrograms();
    }

    public void switchProgram(String programPath) {
        projectOps.switchProgram(programPath);
    }

    public ProgramInfo getProgramInfo() {
        return projectOps.getProgramInfo();
    }

    public String[] listRepos() throws Exception {
        return projectOps.listRepos();
    }

    public void save() throws Exception {
        projectOps.save();
    }

    /** Check in (commit) the checked-out server program as a new server version. */
    public String commit(String message) throws Exception {
        return projectOps.checkinServerProgram(message);
    }

    public void close(boolean save) {
        projectOps.close(save);
    }

    public boolean isReadOnly() {
        return ctx.isReadOnly();
    }

    // ============== FunctionOps (14 methods) ==============

    public ListFunctionsResult listFunctions(int offset, int limit, String filter, String regex, String namespace, boolean includeChildren) {
        return functionOps.listFunctions(offset, limit, filter, regex, namespace, includeChildren);
    }

    public Function getFunction(String address, String name) {
        return functionOps.getFunction(address, name);
    }

    public FunctionListEntry getFunctionListEntry(Function func) {
        return functionOps.getFunctionListEntry(func);
    }

    public FunctionInfo getFunctionInfo(Function func) {
        return functionOps.getFunctionInfo(func);
    }

    public DecompileResult decompile(Function func, int timeout) {
        return functionOps.decompile(func, timeout);
    }

    public BatchDecompileResult batchDecompile(List<String> addresses, List<String> names, String filter, String regex,
                                                String namespace, String startAddress, String endAddress,
                                                int limit, int decompileTimeout, boolean simplify) {
        return functionOps.batchDecompile(addresses, names, filter, regex, namespace, startAddress, endAddress,
                                          limit, decompileTimeout, simplify);
    }

    public FunctionSummary getFunctionSummary(String address, String name, boolean includeStrings,
                                               boolean includeXrefs, int maxCalls, int maxCallers) throws Exception {
        return functionOps.getFunctionSummary(address, name, includeStrings, includeXrefs, maxCalls, maxCallers);
    }

    public List<BasicBlockInfo> getBasicBlocks(String address, String name) throws Exception {
        return functionOps.getBasicBlocks(address, name);
    }

    public CallGraphResult getCallGraph(String address, String name, int depth, String direction, int maxNodes) throws Exception {
        return functionOps.getCallGraph(address, name, depth, direction, maxNodes);
    }

    public CallPathResult findCallPath(String fromSpec, String toSpec, int maxDepth) throws Exception {
        return functionOps.findCallPath(fromSpec, toSpec, maxDepth);
    }

    public List<FunctionInfo> findFunctionsMatching(List<String> calls, List<String> notCalls,
                                                     String referencesString, String inNamespace,
                                                     int sizeMin, int sizeMax, int limit) {
        return functionOps.findFunctionsMatching(calls, notCalls, referencesString, inNamespace, sizeMin, sizeMax, limit);
    }

    public FunctionInfo createFunction(String addressStr, String name) throws Exception {
        return functionOps.createFunction(addressStr, name);
    }

    public void deleteFunction(String addressStr) throws Exception {
        functionOps.deleteFunction(addressStr);
    }

    public List<LineMapping> getLineMappings(String addressStr, String name, int timeout) throws Exception {
        return functionOps.getLineMappings(addressStr, name, timeout);
    }

    // ============== SymbolOps (25 methods) ==============

    public void renameSymbol(String addressStr, String newName, String type, String description) throws Exception {
        symbolOps.renameSymbol(addressStr, newName, type, description);
    }

    public List<SymbolInfo> listSymbols(int offset, int limit, String filter, String regex, String type) {
        return symbolOps.listSymbols(offset, limit, filter, regex, type);
    }

    public BatchRenameResult batchRename(List<RenameMapping> mappings, boolean dryRun, String description) throws Exception {
        return symbolOps.batchRename(mappings, dryRun, description);
    }

    public void setComment(String addressStr, String comment, String type) throws Exception {
        symbolOps.setComment(addressStr, comment, type);
    }

    public void deleteComment(String addressStr, String type) throws Exception {
        symbolOps.deleteComment(addressStr, type);
    }

    public List<CommentInfo> listComments(int offset, int limit, String type, String inFunction) {
        return symbolOps.listComments(offset, limit, type, inFunction);
    }

    public void addBookmark(String addressStr, String type, String category, String comment) throws Exception {
        symbolOps.addBookmark(addressStr, type, category, comment);
    }

    public void deleteBookmark(String addressStr, String type) throws Exception {
        symbolOps.deleteBookmark(addressStr, type);
    }

    public List<BookmarkInfo> listBookmarks(int offset, int limit, String type, String category) {
        return symbolOps.listBookmarks(offset, limit, type, category);
    }

    public void createLabel(String addressStr, String name, String namespace, boolean primary) throws Exception {
        symbolOps.createLabel(addressStr, name, namespace, primary);
    }

    public void deleteLabel(String addressStr, String name) throws Exception {
        symbolOps.deleteLabel(addressStr, name);
    }

    public List<ImportInfo> listImports(int offset, int limit, String filter, String regex) {
        return symbolOps.listImports(offset, limit, filter, regex);
    }

    public List<ExportInfo> listExports(int offset, int limit, String filter, String regex) {
        return symbolOps.listExports(offset, limit, filter, regex);
    }

    public List<NamespaceInfo> listNamespaces(int offset, int limit, String filter, String regex) {
        return symbolOps.listNamespaces(offset, limit, filter, regex);
    }

    public NamespaceResult createNamespace(String name, String parent, boolean isClass) throws Exception {
        return symbolOps.createNamespace(name, parent, isClass);
    }

    public MoveSymbolResult moveSymbolToNamespace(String addressStr, String namespaceName, String type) throws Exception {
        return symbolOps.moveSymbolToNamespace(addressStr, namespaceName, type);
    }

    public void renameNamespace(String oldName, String newName) throws Exception {
        symbolOps.renameNamespace(oldName, newName);
    }

    public ClassInfo getClassInfo(String name) throws Exception {
        return symbolOps.getClassInfo(name);
    }

    public ListEquatesResult listEquates(int offset, int limit, String filter, String regex, Long value) {
        return symbolOps.listEquates(offset, limit, filter, regex, value);
    }

    public void setEquate(String addressStr, int operandIndex, long value, String name) throws Exception {
        symbolOps.setEquate(addressStr, operandIndex, value, name);
    }

    public void deleteEquate(String addressStr, int operandIndex, String name) throws Exception {
        symbolOps.deleteEquate(addressStr, operandIndex, name);
    }

    public FunctionAttributesResult setFunctionAttributes(String address, String name,
            String callingConvention, Boolean noReturn, Boolean inline, Boolean varArgs) throws Exception {
        return symbolOps.setFunctionAttributes(address, name, callingConvention, noReturn, inline, varArgs);
    }

    public List<String> addFunctionTag(String address, String name, String tag) throws Exception {
        return symbolOps.addFunctionTag(address, name, tag);
    }

    public List<String> removeFunctionTag(String address, String name, String tag) throws Exception {
        return symbolOps.removeFunctionTag(address, name, tag);
    }

    public BatchTagResult batchTagSymbols(JsonArray operations) throws Exception {
        return symbolOps.batchTagSymbols(operations);
    }

    // ============== DataTypeOps (12 methods) ==============

    public ListDataTypesResult listDataTypes(int offset, int limit, String filter, String regex, String category) {
        return dataTypeOps.listDataTypes(offset, limit, filter, regex, category);
    }

    public DataTypeDetail getDataType(String name, String category) throws Exception {
        return dataTypeOps.getDataType(name, category);
    }

    public StructureResult createStructure(String name, String category, List<StructField> fields, boolean packed) throws Exception {
        return dataTypeOps.createStructure(name, category, fields, packed);
    }

    public StructureResult updateStructure(String name, String category, String operation,
                                            List<StructField> fields, String fieldName, boolean force) throws Exception {
        return dataTypeOps.updateStructure(name, category, operation, fields, fieldName, force);
    }

    public Map<String, Object> exportTypeArchive(String archivePath, List<String> categories) throws Exception {
        return dataTypeOps.exportTypeArchive(archivePath, categories);
    }

    public Map<String, Object> importTypeArchive(String archivePath, List<String> categories) throws Exception {
        return dataTypeOps.importTypeArchive(archivePath, categories);
    }

    public void renameStructField(String structName, String fieldName, String newName, String category) throws Exception {
        dataTypeOps.renameStructField(structName, fieldName, newName, category);
    }

    public DataTypeResult createEnum(String name, Map<String, Long> values, String category, int size) throws Exception {
        return dataTypeOps.createEnum(name, values, category, size);
    }

    public DataTypeResult createUnion(String name, List<StructField> fields, String category) throws Exception {
        return dataTypeOps.createUnion(name, fields, category);
    }

    public DataTypeResult createTypedef(String name, String baseTypeName, String category) throws Exception {
        return dataTypeOps.createTypedef(name, baseTypeName, category);
    }

    public void deleteDataType(String name, String category) throws Exception {
        dataTypeOps.deleteDataType(name, category);
    }

    public void setDataType(String addressStr, String dataTypeName, int length) throws Exception {
        dataTypeOps.setDataType(addressStr, dataTypeName, length);
    }

    public DataValueResult readDataValue(String addressStr) {
        return dataTypeOps.readDataValue(addressStr);
    }

    public void setPrototype(String functionAddress, String prototype, String description) throws Exception {
        dataTypeOps.setPrototype(functionAddress, prototype, description);
    }

    public void setCustomSignature(String functionAddress, String returnType, List<CustomParameter> parameters, String description) throws Exception {
        dataTypeOps.setCustomSignature(functionAddress, returnType, parameters, description);
    }

    // ============== MemoryOps (14 methods) ==============

    public byte[] readMemory(String addressStr, int length) throws Exception {
        return memoryOps.readMemory(addressStr, length);
    }

    public List<DisassemblyLine> getDisassembly(String addressStr, int count, int context) throws Exception {
        return memoryOps.getDisassembly(addressStr, count, context);
    }

    public int disassemble(String addressStr, int length) throws Exception {
        return memoryOps.disassemble(addressStr, length);
    }

    public void clearListing(String startAddressStr, String endAddressStr) throws Exception {
        memoryOps.clearListing(startAddressStr, endAddressStr);
    }

    public List<SegmentInfo> listSegments() {
        return memoryOps.listSegments();
    }

    public List<StringInfo> listStrings(int offset, int limit, int minLength, String filter, String regex) {
        return memoryOps.listStrings(offset, limit, minLength, filter, regex);
    }

    public List<XRef> getXrefs(String addressStr, String direction, int limit) {
        return memoryOps.getXrefs(addressStr, direction, limit);
    }

    public List<XRef> getXrefs(String addressStr, String direction, int limit, List<String> refTypes) {
        return memoryOps.getXrefs(addressStr, direction, limit, refTypes);
    }

    public List<XRefWithContext> getXrefsWithContext(String addressStr, String direction, int contextLines,
                                                      String contextPattern, int limit) throws Exception {
        return memoryOps.getXrefsWithContext(addressStr, direction, contextLines, contextPattern, limit);
    }

    public List<XRefWithContext> getXrefsWithContext(String addressStr, String direction, int contextLines,
                                                      String contextPattern, int limit, List<String> refTypes) throws Exception {
        return memoryOps.getXrefsWithContext(addressStr, direction, contextLines, contextPattern, limit, refTypes);
    }

    public Map<String, Object> getDataAtAddress(String addressStr, int lookAhead) throws Exception {
        return memoryOps.getDataAtAddress(addressStr, lookAhead);
    }

    public List<Map<String, Object>> getSymbolsAfter(String addressStr, int count) throws Exception {
        return memoryOps.getSymbolsAfter(addressStr, count);
    }

    public Map<String, Object> detectTable(String addressStr, int maxEntries, boolean applyType, String name) throws Exception {
        return memoryOps.detectTable(addressStr, maxEntries, applyType, name);
    }

    public List<GlobalVariableInfo> getGlobalVariables(int offset, int limit, String filter) {
        return memoryOps.getGlobalVariables(offset, limit, filter);
    }

    public GlobalVariablesResult getGlobalVariablesWithTotal(int offset, int limit, String filter, String regex, String segment, String sortBy, String dataTypeFilter) {
        return memoryOps.getGlobalVariablesWithTotal(offset, limit, filter, regex, segment, sortBy, dataTypeFilter);
    }

    // ============== AnalysisOps (15 methods) ==============

    public SearchResponse search(String filter, String regex, String hexPattern, List<String> types,
                                  boolean caseSensitive, int limit, int offset,
                                  boolean countOnly, boolean includeContext,
                                  String scopeType, String scopeValue,
                                  String scopeStartAddress, String scopeEndAddress,
                                  String functionFilter, String searchMode, String flowType) {
        return analysisOps.search(filter, regex, hexPattern, types, caseSensitive, limit, offset,
                                  countOnly, includeContext, scopeType, scopeValue,
                                  scopeStartAddress, scopeEndAddress, functionFilter, searchMode, flowType);
    }

    public AnalysisHints getAnalysisHints(String address, String functionName) throws Exception {
        return analysisOps.getAnalysisHints(address, functionName);
    }

    public DataFlowResult traceDataFlow(String fromStr, int depth, boolean includeCalls) throws Exception {
        return analysisOps.traceDataFlow(fromStr, depth, includeCalls);
    }

    public PcodeResult getPcode(String address, String name, boolean highLevel) throws Exception {
        return analysisOps.getPcode(address, name, highLevel);
    }

    public StackFrameResult getStackFrame(String address, String name) throws Exception {
        return analysisOps.getStackFrame(address, name);
    }

    public SwitchTableResult getSwitchTable(String addressStr) throws Exception {
        return analysisOps.getSwitchTable(addressStr);
    }

    public SwitchOverrideResult setSwitchOverride(String addressStr, List<String> caseAddresses) throws Exception {
        return analysisOps.setSwitchOverride(addressStr, caseAddresses);
    }

    public ScriptResult executeScript(String code, int timeout, boolean sandbox) throws Exception {
        return analysisOps.executeScript(code, timeout, sandbox);
    }

    public ScriptResult executePythonScript(String code, String filePath, int timeout, boolean sandbox) throws Exception {
        return analysisOps.executePythonScript(code, filePath, timeout, sandbox);
    }

    public UndoRedoResult undo() throws Exception {
        return analysisOps.undo();
    }

    public UndoRedoResult redo() throws Exception {
        return analysisOps.redo();
    }

    public UndoHistoryResult getUndoHistory() {
        return analysisOps.getUndoHistory();
    }

    public ReanalyzeResult reanalyze(String addressStr) throws Exception {
        return analysisOps.reanalyze(addressStr);
    }

    public ExportAllCResult exportAllC(int timeout, boolean includeTypes, boolean includeHeaders) {
        return analysisOps.exportAllC(timeout, includeTypes, includeHeaders);
    }

    public void setFunctionVariableName(String functionAddressStr, String oldName, String newName, String description) throws Exception {
        analysisOps.setFunctionVariableName(functionAddressStr, oldName, newName, description);
    }

    public void setFunctionVariableType(String functionAddressStr, String variableName, String dataTypeName, String description) throws Exception {
        analysisOps.setFunctionVariableType(functionAddressStr, variableName, dataTypeName, description, true);
    }

    public void setFunctionVariableType(String functionAddressStr, String variableName, String dataTypeName, String description, boolean forceRemoveConflicts) throws Exception {
        analysisOps.setFunctionVariableType(functionAddressStr, variableName, dataTypeName, description, forceRemoveConflicts);
    }

    // ============== VersionTrackingOps ==============

    public JsonObject vtCreateSession(String sourcePath, String destPath) throws Exception {
        return vtOps.createSession(sourcePath, destPath);
    }

    public JsonObject vtRunCorrelator(String correlatorName) throws Exception {
        return vtOps.runCorrelator(correlatorName);
    }

    public JsonObject vtListMatches(double minScore, int limit) throws Exception {
        return vtOps.listMatches(minScore, limit);
    }

    public JsonObject vtAcceptMatches(boolean acceptAll, double minScore) throws Exception {
        return vtOps.acceptMatches(acceptAll, minScore);
    }

    public JsonObject vtApplyMarkup() throws Exception {
        return vtOps.applyMarkup();
    }

    public JsonObject vtGetCorrelators() {
        return vtOps.getAvailableCorrelators();
    }

    // ====================================================================
    //  STATIC INNER DTO CLASSES
    //  Referenced as GhidraEngine.FunctionInfo, GhidraEngine.ProgramInfo, etc.
    //  by CommandHandler and all operation classes.
    // ====================================================================

    public static class ProgramInfo {
        public String name;
        public String path;
        public String format;
        public String languageId;
        public String compiler;
        public String imageBase;
        public String minAddress;
        public String maxAddress;
        public String endianness;
        public int pointerSize;
        public Integer version;
        public Integer latestVersion;
    }

    public static class FunctionInfo {
        public String name;
        public String address;
        public String entryPoint;
        public String signature;
        public String returnType;
        public String callingConvention;
        public int size;
        public boolean isThunk;
        public boolean isExternal;
        public boolean hasVarArgs;
        public String namespace;
        public String comment;
        public String sourceFile;   // Source file path from DWARF/debug info
        public Integer sourceLine;  // Source line number from DWARF/debug info
        public String sourceInfo;   // Additional source info (comments, tags)
        public List<ParameterInfo> parameters;
        public List<VariableInfo> localVariables;
        public List<JsonObject> tags;  // Structured tags [{type, data?}]
    }

    /**
     * Result of listing functions with pagination info
     */
    /**
     * Lightweight function entry for list_functions (no locals, no comment, no source info)
     */
    public static class FunctionListEntry {
        public String name;
        public String address;
        public String signature;
        public String returnType;
        public String callingConvention;
        public int parameterCount;
        public int size;
        public boolean isThunk;
        public boolean isExternal;
        public boolean hasVarArgs;
        public String namespace;
        public List<JsonObject> tags;
    }

    public static class ListFunctionsResult {
        public List<FunctionInfo> functions;
        public int total;

        public ListFunctionsResult(List<FunctionInfo> functions, int total) {
            this.functions = functions;
            this.total = total;
        }
    }

    public static class ListDataTypesResult {
        public List<DataTypeInfo> dataTypes;
        public int total;

        public ListDataTypesResult(List<DataTypeInfo> dataTypes, int total) {
            this.dataTypes = dataTypes;
            this.total = total;
        }
    }

    public static class BatchDecompileResult {
        public List<DecompileResult> results = new ArrayList<>();
        public List<BatchDecompileFailure> failed = new ArrayList<>();
        public int total;
        public int decompiled;
    }

    public static class BatchDecompileFailure {
        public String address;
        public String name;
        public String error;
    }

    public static class ParameterInfo {
        public String name;
        public String dataType;
        public int size;
        public int ordinal;
        public String storage;
        public Integer stackOffset;
    }

    public static class VariableInfo {
        public String name;
        public String dataType;
        public int size;
        public String storage;
        public Integer stackOffset;
    }

    public static class NamespaceInfo {
        public String name;
        public String fullPath;
        public String address;
        public String parentNamespace;
        public boolean isClass;
        public int functionCount;
    }

    public static class DecompileResult {
        public String functionName;
        public String address;
        public String signature;
        public String pseudocode;
        public List<String> warnings;
        public List<JsonObject> tags;  // Structured tags [{type, data?}]
    }

    public static class XRef {
        public String fromAddress;
        public String toAddress;
        public String type;
        public boolean isCall;
        public boolean isPrimary;
        public String fromFunction;
        public String toFunction;
    }

    public static class StringInfo {
        public String address;
        public String value;
        public int length;
        public String encoding;
        public String inFunction;
        public int xrefCount;
    }

    public static class SegmentInfo {
        public String name;
        public String start;
        public String end;
        public long size;
        public String permissions;
        public boolean isInitialized;
        public boolean isVolatile;
        public boolean isMapped;
    }

    public static class ImportInfo {
        public String name;
        public String address;
        public String library;
    }

    public static class ExportInfo {
        public String name;
        public String address;
    }

    public static class SearchResult {
        public String type;      // "function", "string", "symbol", "import", "export", "data", "comment", "namespace"
        public String name;      // The matched name/value
        public String address;
        public JsonObject context;  // Type-specific context (signature, xrefs, etc.)
    }

    public static class SearchResponse {
        public List<SearchResult> results;
        public int total;      // Actual total number of matches (not capped by limit)
        public boolean hasMore; // Whether there are more results beyond this page
    }

    /**
     * Tracks pagination state across multiple search type passes.
     * Each searchXxx method calls addMatch() for every match found.
     * The context handles offset skipping, limit capping, and total counting.
     */
    public static class SearchContext {
        final List<SearchResult> results = new ArrayList<>();
        final int offset;
        final int limit;
        final boolean countOnly;
        final boolean includeContext;
        int totalMatches = 0;
        int skipped = 0;

        public SearchContext(int offset, int limit, boolean countOnly, boolean includeContext) {
            this.offset = offset;
            this.limit = limit;
            this.countOnly = countOnly;
            this.includeContext = includeContext;
        }

        /** Whether the result page is full — use for early termination when countOnly is false. */
        public boolean isFull() {
            return !countOnly && results.size() >= limit;
        }

        /** Whether the next match will actually land in the result page. */
        public boolean willCollect() {
            return !countOnly && skipped >= offset && results.size() < limit;
        }

        /**
         * Record a match. Always increments totalMatches.
         * Only adds to results if we're past offset and under limit and not countOnly.
         */
        public void addMatch(SearchResult result) {
            totalMatches++;
            if (countOnly) return;
            if (skipped < offset) {
                skipped++;
                return;
            }
            if (results.size() < limit) {
                results.add(result);
            }
        }

        public SearchResponse toResponse() {
            SearchResponse resp = new SearchResponse();
            resp.results = results;
            resp.total = totalMatches;
            resp.hasMore = !countOnly && totalMatches > offset + results.size();
            return resp;
        }
    }

    public static class StructField {
        public String name;
        public String dataType;
        public int offset = -1;
        public String comment;
        // updateFields-specific: identify field and apply partial updates
        public String fieldName;    // identify by existing name
        public String newName;      // rename to this
        public String newDataType;  // retype to this
    }

    public static class StructureResult {
        public String name;
        public String category;
        public int size;
        public String warning;  // deprecation warning for old operation names
    }

    public static class CustomParameter {
        public String name;
        public String dataType;
        public String storage;  // e.g., "EAX", "ECX", "EDX", "stack:0x4", etc.
    }

    public static class DataTypeResult {
        public String name;
        public String category;
        public int size;
    }

    public static class SymbolInfo {
        public String name;
        public String address;
        public String type;
        public boolean isPrimary;
        public boolean isExternal;
        public String namespace;
        public List<JsonObject> tags;  // Structured tags [{type, data?}]
    }

    public static class DisassemblyLine {
        public String address;
        public String mnemonic;
        public String operands;
        public String bytes;
        public String comment;
        public String inFunction;
    }

    public static class FunctionSummary {
        public String name;
        public String address;
        public String signature;
        public int size;
        public List<String> calls;
        public List<String> callers;
        public List<String> strings;
        public int xrefToCount;
        public int xrefFromCount;
        public int localVarCount;
        public int parameterCount;
    }

    public static class DataTypeInfo {
        public String name;
        public String category;
        public int size;
        public String description;
        public String type;
    }

    public static class DataTypeDetail {
        public String name;
        public String category;
        public int size;
        public String description;
        public int alignment;
        public String type;
        public List<FieldDetail> fields;
        public List<EnumValueDetail> values;
        public String underlyingType;
        // FunctionDefinition fields
        public String returnType;
        public List<FunctionParamDetail> parameters;
        public String callingConvention;
        public boolean hasVarArgs;

        public static class EnumValueDetail {
            public String name;
            public long value;
        }
    }

    public static class FunctionParamDetail {
        public String name;
        public String dataType;
        public int ordinal;
    }

    public static class FieldDetail {
        public String name;
        public String dataType;
        public int offset;
        public int size;
        public String comment;
    }

    public static class CommentInfo {
        public String address;
        public String comment;
        public String type;
        public String inFunction;
    }

    public static class BookmarkInfo {
        public String address;
        public String type;
        public String category;
        public String comment;
        public String inFunction;
    }

    public static class BasicBlockInfo {
        public String startAddress;
        public String endAddress;
        public long size;
        public List<String> successors;
        public List<String> predecessors;
    }

    public static class CallGraphResult {
        public String rootFunction;
        public String rootAddress;
        public List<CallGraphNode> nodes;
        public List<CallGraphEdge> edges;
        public boolean truncated;
    }

    public static class CallGraphNode {
        public String name;
        public String address;
    }

    public static class CallGraphEdge {
        public String from;
        public String to;
        public String type;
    }

    public static class CallPathResult {
        public String from;
        public String to;
        public boolean found;
        public List<List<String>> paths;
    }

    public static class XRefWithContext {
        public String fromAddress;
        public String toAddress;
        public String type;
        public boolean isCall;
        public String fromFunction;
        public String toFunction;
        public List<String> context;
    }

    public static class ClassInfo {
        public String name;
        public String fullPath;
        public boolean isClass;
        public String parentClass;
        public List<FunctionInfo> methods;
    }

    public static class PcodeVarnode {
        public String space;
        public long offset;
        public int size;
    }

    public static class PcodeOp {
        public String address;
        public int seqNum;
        public String mnemonic;
        public PcodeVarnode output;
        public List<PcodeVarnode> inputs;
        public int blockIndex = -1;
    }

    public static class SymbolEntry {
        public String name;
        public String dataType;
        public PcodeVarnode storage;
        public String category;
        public int paramIndex;
    }

    public static class PcodeBlockInfo {
        public int index;
        public List<Integer> successors;
    }

    public static class PcodeResult {
        public String functionName;
        public String address;
        public String signature;
        public String callingConvention;
        public List<PcodeOp> operations;
        public List<SymbolEntry> symbols;
        public List<PcodeBlockInfo> blocks;
    }

    public static class RenameMapping {
        public String address;
        public String newName;
    }

    public static class BatchRenameResult {
        public boolean dryRun;
        public List<String> succeeded;
        public List<String> failed;
    }

    public static class DataFlowResult {
        public String from;
        public List<DataFlowNode> flows;
    }

    public static class DataFlowNode {
        public String address;
        public String description;
        public List<String> uses;
    }

    public static class AnalysisHints {
        public String functionName;
        public String address;
        public List<String> hints;
    }

    public static class ScriptResult {
        public boolean success;
        public String output;
        public String error;
    }

    public static class LineMapping {
        public int line;
        public int column;
        public String address;
        public String text;
    }

    public static class GlobalVariableInfo {
        public String name;
        public String address;
        public String dataType;
        public int size;
        public String namespace;
        public boolean isInitialized;
        public int xrefCount;
        public List<String> referencingFunctions;  // Function names that reference this data
        public String value;  // String representation of the value if available
    }

    public static class GlobalVariablesResult {
        public List<GlobalVariableInfo> globals;
        public int total;

        public GlobalVariablesResult(List<GlobalVariableInfo> globals, int total) {
            this.globals = globals;
            this.total = total;
        }
    }

    public static class DataValueResult {
        public String kind;        // "scalar", "string", "pointer", "array", "struct", "enum"
        public String value;       // for scalar/string/pointer/enum
        public List<DataValueResult> elements;  // for array
        public List<DataValueField> fields;     // for struct

        public static DataValueResult scalar(String value) {
            DataValueResult r = new DataValueResult();
            r.kind = "scalar";
            r.value = value;
            return r;
        }

        public static DataValueResult string(String value) {
            DataValueResult r = new DataValueResult();
            r.kind = "string";
            r.value = value;
            return r;
        }

        public static DataValueResult pointer(String value) {
            DataValueResult r = new DataValueResult();
            r.kind = "pointer";
            r.value = value;
            return r;
        }

        public static DataValueResult array(List<DataValueResult> elements) {
            DataValueResult r = new DataValueResult();
            r.kind = "array";
            r.elements = elements;
            return r;
        }

        public static DataValueResult struct(List<DataValueField> fields) {
            DataValueResult r = new DataValueResult();
            r.kind = "struct";
            r.fields = fields;
            return r;
        }

        public static DataValueResult enumVal(String value) {
            DataValueResult r = new DataValueResult();
            r.kind = "enum";
            r.value = value;
            return r;
        }
    }

    public static class DataValueField {
        public String name;
        public DataValueResult value;

        public DataValueField(String name, DataValueResult value) {
            this.name = name;
            this.value = value;
        }
    }

    public static class EquateInfo {
        public String name;
        public long value;
        public String hexValue;
        public int referenceCount;
        public List<String> references;
    }

    public static class ListEquatesResult {
        public List<EquateInfo> equates;
        public int total;
    }

    public static class FunctionAttributesResult {
        public String name;
        public String address;
        public String callingConvention;
        public boolean noReturn;
        public boolean isInline;
        public boolean varArgs;
    }

    public static class BatchTagResult {
        public boolean success;
        public int applied;
        public List<FailedTagOperation> failed = new ArrayList<>();
    }

    public static class FailedTagOperation {
        public String address;
        public String error;
    }

    public static class NamespaceResult {
        public String name;
        public String parentNamespace;
        public boolean isClass;
    }

    public static class MoveSymbolResult {
        public String name;
        public String oldNamespace;
        public String newNamespace;
    }

    public static class UndoRedoResult {
        public String actionName;
        public boolean canUndo;
        public boolean canRedo;
    }

    public static class UndoHistoryResult {
        public List<String> undoStack;
        public List<String> redoStack;
        public boolean canUndo;
        public boolean canRedo;
    }

    public static class StackFrameResult {
        public int frameSize;
        public int localSize;
        public int parameterSize;
        public int returnAddrOffset;
        public List<StackVariableInfo> variables;
    }

    public static class StackVariableInfo {
        public int offset;
        public String name;
        public String dataType;
        public int size;
        public String comment;
        public boolean isParameter;
    }

    public static class ReanalyzeResult {
        public boolean success;
        public String scope;
    }

    public static class SwitchTableResult {
        public String switchAddress;
        public int numCases;
        public List<SwitchCase> cases;
        public String defaultAddress;
    }

    public static class SwitchCase {
        public long value;
        public String targetAddress;
        public String targetLabel;
    }

    public static class SwitchOverrideResult {
        public boolean success;
        public String address;
        public int numCases;
        public String functionName;
    }

    public static class ExportAllCResult {
        public long cacheVersion;
        public int functionCount;
        public int typeCount;
        public String headerCode;
        public String implementationCode;
        public List<ExportedFunction> functions;
    }

    public static class ExportedFunction {
        public String name;
        public String address;
        public String signature;
        public String namespace;
        public String code;
        public boolean success;
        public String error;
    }
}
