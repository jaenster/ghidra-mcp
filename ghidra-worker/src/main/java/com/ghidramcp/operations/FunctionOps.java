package com.ghidramcp.operations;

import com.ghidramcp.GhidraContext;
import com.ghidramcp.GhidraEngine;

import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.*;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

/**
 * Function-related operations: listing, lookup, decompilation, call graph,
 * basic blocks, path finding, matching, create/delete, and line mappings.
 */
public class FunctionOps {

    private final GhidraContext ctx;

    public FunctionOps(GhidraContext ctx) {
        this.ctx = ctx;
    }

    // ==================== LISTING & LOOKUP ====================

    /**
     * List functions with optional filtering (single-pass with running total)
     */
    public GhidraEngine.ListFunctionsResult listFunctions(int offset, int limit, String filter, String regex, String namespace, boolean includeChildren) {
        List<GhidraEngine.FunctionInfo> functions = new ArrayList<>();
        FunctionManager fm = ctx.getProgram().getFunctionManager();
        Object[] filterArgs = GhidraContext.prepareFilter(filter, regex);
        String filterLower = (String) filterArgs[0];
        Pattern compiled = (Pattern) filterArgs[1];

        Iterator<Function> iter = fm.getFunctions(true);
        int total = 0;
        int skipped = 0;

        while (iter.hasNext()) {
            Function func = iter.next();

            // Apply name filter (substring + regex)
            if (!GhidraContext.passesFilter(func.getName(), filterLower, compiled)) continue;

            // Apply namespace filter
            if (namespace != null) {
                Namespace ns = func.getParentNamespace();
                if (ns == null) continue;
                String nsPath = ns.isGlobal() ? "" : ns.getName(true);
                if (includeChildren) {
                    if (!nsPath.equals(namespace) && !nsPath.startsWith(namespace + "::")) continue;
                } else {
                    if (!nsPath.equals(namespace)) continue;
                }
            }

            total++;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (functions.size() < limit) {
                functions.add(getFunctionInfo(func));
            }
        }

        return new GhidraEngine.ListFunctionsResult(functions, total);
    }

    /**
     * Get function by address or name
     */
    public Function getFunction(String address, String name) {
        var fm = ctx.getProgram().getFunctionManager();
        if (address != null) {
            Address addr = ctx.parseAddress(address);
            Function f = fm.getFunctionAt(addr);
            if (f == null) {
                // Resolve a mid-function address to its containing function's entry,
                // so decompile/get_function_info work for any address inside a function.
                f = fm.getFunctionContaining(addr);
            }
            return f;
        } else if (name != null) {
            // Accept either the simple name ("FN") or the fully-namespaced form
            // ("Storm::Source::SFile::FN") that list_symbols / list_functions emit.
            // An exact namespaced match wins (also disambiguates duplicate simple
            // names across namespaces); otherwise fall back to the first simple match.
            Function simpleMatch = null;
            Iterator<Function> iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                if (func.getName(true).equals(name)) {
                    return func;
                }
                if (simpleMatch == null && func.getName().equals(name)) {
                    simpleMatch = func;
                }
            }
            return simpleMatch;
        }
        return null;
    }

    /**
     * Get lightweight function entry for listing (no locals, no comment, no source)
     */
    public GhidraEngine.FunctionListEntry getFunctionListEntry(Function func) {
        GhidraEngine.FunctionListEntry entry = new GhidraEngine.FunctionListEntry();
        entry.name = func.getName();
        entry.address = func.getEntryPoint().toString();
        entry.signature = func.getSignature().getPrototypeString();
        entry.returnType = func.getReturnType().getName();
        entry.callingConvention = func.getCallingConventionName();
        entry.parameterCount = func.getParameterCount();
        entry.size = (int) func.getBody().getNumAddresses();
        entry.isThunk = func.isThunk();
        entry.isExternal = func.isExternal();
        entry.hasVarArgs = func.hasVarArgs();

        Namespace ns = func.getParentNamespace();
        if (ns != null && !ns.isGlobal()) {
            entry.namespace = ns.getName(true);
        }

        List<JsonObject> parsedTags = ctx.parseStructuredTags(func);
        if (!parsedTags.isEmpty()) {
            entry.tags = parsedTags;
        }

        return entry;
    }

    /**
     * Get detailed function information
     */
    public GhidraEngine.FunctionInfo getFunctionInfo(Function func) {
        GhidraEngine.FunctionInfo info = new GhidraEngine.FunctionInfo();
        info.name = func.getName();
        info.address = func.getEntryPoint().toString();
        info.entryPoint = func.getEntryPoint().toString();
        info.signature = func.getSignature().getPrototypeString();
        info.returnType = func.getReturnType().getName();
        info.callingConvention = func.getCallingConventionName();
        info.size = (int) func.getBody().getNumAddresses();
        info.isThunk = func.isThunk();
        info.isExternal = func.isExternal();
        info.hasVarArgs = func.hasVarArgs();

        // Get namespace (full path for proper folder structure)
        Namespace ns = func.getParentNamespace();
        if (ns != null && !ns.isGlobal()) {
            info.namespace = ns.getName(true);  // Full path like "Quests::A1Q0"
        }

        // Get parameters
        info.parameters = new ArrayList<>();
        for (Parameter param : func.getParameters()) {
            GhidraEngine.ParameterInfo pinfo = new GhidraEngine.ParameterInfo();
            pinfo.name = param.getName();
            pinfo.dataType = param.getDataType().getName();
            pinfo.size = param.getLength();
            pinfo.ordinal = param.getOrdinal();
            pinfo.storage = param.getVariableStorage().toString();
            pinfo.stackOffset = param.isStackVariable() ? param.getStackOffset() : null;
            info.parameters.add(pinfo);
        }

        // Get local variables
        info.localVariables = new ArrayList<>();
        for (Variable var : func.getLocalVariables()) {
            GhidraEngine.VariableInfo vinfo = new GhidraEngine.VariableInfo();
            vinfo.name = var.getName();
            vinfo.dataType = var.getDataType().getName();
            vinfo.size = var.getLength();
            vinfo.storage = var.getVariableStorage().toString();
            vinfo.stackOffset = var.isStackVariable() ? var.getStackOffset() : null;
            info.localVariables.add(vinfo);
        }

        // PAINPOINT #31: enrich undefined* types with the decompiler-resolved type.
        // Build a name→resolvedType map from the HighFunction; only run if any
        // local/param has an undefined* raw type (avoids needless decompile cost).
        boolean hasUndefined = false;
        for (GhidraEngine.VariableInfo v : info.localVariables)
            if (v.dataType != null && v.dataType.startsWith("undefined")) { hasUndefined = true; break; }
        if (!hasUndefined) {
            for (GhidraEngine.ParameterInfo p : info.parameters)
                if (p.dataType != null && p.dataType.startsWith("undefined")) { hasUndefined = true; break; }
        }
        if (hasUndefined) {
            try {
                DecompileResults dr = ctx.getDecompiler().decompileFunction(func, 30, ctx.getMonitor());
                if (dr != null && dr.decompileCompleted()) {
                    HighFunction hf = dr.getHighFunction();
                    if (hf != null) {
                        Map<String, String> resolvedByName = new HashMap<>();
                        LocalSymbolMap lsm = hf.getLocalSymbolMap();
                        Iterator<HighSymbol> sit = lsm.getSymbols();
                        while (sit.hasNext()) {
                            HighSymbol hs = sit.next();
                            String dt = hs.getDataType() != null ? hs.getDataType().getName() : null;
                            if (dt != null && !dt.startsWith("undefined"))
                                resolvedByName.put(hs.getName(), dt);
                        }
                        for (GhidraEngine.VariableInfo v : info.localVariables) {
                            if (v.dataType != null && v.dataType.startsWith("undefined")) {
                                String resolved = resolvedByName.get(v.name);
                                if (resolved != null)
                                    v.dataType = v.dataType + " /* resolvedType: " + resolved + " */";
                            }
                        }
                        for (GhidraEngine.ParameterInfo p : info.parameters) {
                            if (p.dataType != null && p.dataType.startsWith("undefined")) {
                                String resolved = resolvedByName.get(p.name);
                                if (resolved != null)
                                    p.dataType = p.dataType + " /* resolvedType: " + resolved + " */";
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // best-effort; raw type remains unchanged on error
            }
        }

        // Get comment
        info.comment = func.getComment();

        // Get source file/line info (DWARF debug info if available)
        try {
            Address entryPoint = func.getEntryPoint();
            SourceFileManager sourceManager = ctx.getProgram().getSourceFileManager();

            if (sourceManager != null) {
                // Try to get source mapping for the function entry point
                java.util.List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(entryPoint);

                if (entries != null && !entries.isEmpty()) {
                    SourceMapEntry entry = entries.get(0);
                    ghidra.program.database.sourcemap.SourceFile sourceFile = entry.getSourceFile();
                    if (sourceFile != null) {
                        info.sourceFile = sourceFile.getPath().toString();
                        info.sourceLine = entry.getLineNumber();
                    }
                }
            }

            // Also check plate comments for source info (common DWARF annotation)
            CodeUnit cu = ctx.getProgram().getListing().getCodeUnitAt(entryPoint);
            if (cu != null && info.sourceFile == null) {
                String plateComment = cu.getComment(CodeUnit.PLATE_COMMENT);
                if (plateComment != null) {
                    // Try to parse common source comment formats
                    // e.g., "Source: /path/file.c:123" or "/path/file.c:123"
                    java.util.regex.Pattern srcPattern = java.util.regex.Pattern.compile(
                        "(?:Source:\\s*)?([^:]+\\.[chp]{1,3}p?):(\\d+)", java.util.regex.Pattern.CASE_INSENSITIVE);
                    java.util.regex.Matcher m = srcPattern.matcher(plateComment);
                    if (m.find()) {
                        info.sourceFile = m.group(1);
                        info.sourceLine = Integer.parseInt(m.group(2));
                    } else {
                        // Store raw comment if it looks source-related
                        if (plateComment.contains(".c") || plateComment.contains(".cpp") ||
                            plateComment.contains(".h") || plateComment.contains("line")) {
                            info.sourceInfo = plateComment;
                        }
                    }
                }
            }

            // Check function tags for additional source info
            for (ghidra.program.model.listing.FunctionTag tag : func.getTags()) {
                String tagName = tag.getName();
                if (tagName.startsWith("SOURCE:") || tagName.contains(".c:") ||
                    tagName.contains(".cpp:") || tagName.contains(".h:")) {
                    if (info.sourceInfo == null) {
                        info.sourceInfo = tagName;
                    }
                }
            }
        } catch (Exception e) {
            // Ignore source info errors - debug info may not be available
        }

        // Parse structured tags
        List<JsonObject> parsedTags = ctx.parseStructuredTags(func);
        if (!parsedTags.isEmpty()) {
            info.tags = parsedTags;
        }

        // Record the read so write operations can check freshness
        ctx.recordFunctionRead(func.getEntryPoint().toString(), ctx.getProgram().getModificationNumber());

        return info;
    }

    // ==================== DECOMPILATION ====================

    /**
     * Decompile a function
     */
    public GhidraEngine.DecompileResult decompile(Function func, int timeout) {
        DecompileResults results;

        // Use the pool for parallel-capable decompilation
        com.ghidramcp.DecompilerPool pool = ctx.getDecompilerPool();
        if (pool != null) {
            try {
                results = pool.decompile(func, timeout);
            } catch (Exception e) {
                throw new RuntimeException("Decompilation failed: " + e.getMessage(), e);
            }
        } else {
            results = ctx.getDecompiler().decompileFunction(func, timeout, ctx.getMonitor());
        }

        GhidraEngine.DecompileResult dr = buildDecompileResult(func, results);
        // Record the read so write operations can check freshness
        ctx.recordFunctionRead(func.getEntryPoint().toString(), ctx.getProgram().getModificationNumber());
        return dr;
    }

    /**
     * Build a DecompileResult DTO from raw DecompileResults.
     */
    GhidraEngine.DecompileResult buildDecompileResult(Function func, DecompileResults results) {
        GhidraEngine.DecompileResult result = new GhidraEngine.DecompileResult();
        result.functionName = func.getName();
        result.address = func.getEntryPoint().toString();
        result.signature = func.getSignature().getPrototypeString();

        if (results.decompileCompleted()) {
            result.pseudocode = results.getDecompiledFunction().getC();
        } else {
            result.warnings = new ArrayList<>();
            result.warnings.add(results.getErrorMessage());
        }

        // Parse structured tags
        List<JsonObject> parsedTags = ctx.parseStructuredTags(func);
        if (!parsedTags.isEmpty()) {
            result.tags = parsedTags;
        }

        return result;
    }

    /**
     * Batch decompile multiple functions.
     * Functions selected by explicit address/name list OR by filter/namespace/address range.
     */
    public GhidraEngine.BatchDecompileResult batchDecompile(
            List<String> addresses, List<String> names, String filter, String regex,
            String namespace, String startAddress, String endAddress,
            int limit, int decompileTimeout, boolean simplify) {

        GhidraEngine.BatchDecompileResult result = new GhidraEngine.BatchDecompileResult();
        List<Function> functions = new ArrayList<>();

        // Phase 1: Resolve functions
        if (addresses != null && !addresses.isEmpty()) {
            // Explicit address list
            for (String addr : addresses) {
                Function func = this.getFunction(addr, null);
                if (func != null) {
                    functions.add(func);
                } else {
                    GhidraEngine.BatchDecompileFailure fail = new GhidraEngine.BatchDecompileFailure();
                    fail.address = addr;
                    fail.name = "";
                    fail.error = "Function not found at address: " + addr;
                    result.failed.add(fail);
                }
            }
        } else if (names != null && !names.isEmpty()) {
            // Explicit name list
            for (String name : names) {
                Function func = this.getFunction(null, name);
                if (func != null) {
                    functions.add(func);
                } else {
                    GhidraEngine.BatchDecompileFailure fail = new GhidraEngine.BatchDecompileFailure();
                    fail.address = "";
                    fail.name = name;
                    fail.error = "Function not found: " + name;
                    result.failed.add(fail);
                }
            }
        } else {
            // Filter-based selection
            Address rangeStart = startAddress != null ? ctx.parseAddress(startAddress) : null;
            Address rangeEnd = endAddress != null ? ctx.parseAddress(endAddress) : null;
            Object[] filterArgs = GhidraContext.prepareFilter(filter, regex);
            String filterLower = (String) filterArgs[0];
            Pattern compiled = (Pattern) filterArgs[1];

            Iterator<Function> iter = ctx.getProgram().getFunctionManager().getFunctions(true);
            while (iter.hasNext() && functions.size() < limit) {
                Function func = iter.next();

                // Namespace filter
                if (namespace != null) {
                    Namespace ns = func.getParentNamespace();
                    if (ns == null || ns.isGlobal() || !ns.getName(true).contains(namespace)) {
                        continue;
                    }
                }

                // Address range filter
                if (rangeStart != null && func.getEntryPoint().compareTo(rangeStart) < 0) continue;
                if (rangeEnd != null && func.getEntryPoint().compareTo(rangeEnd) > 0) continue;

                // Name filter
                if (!GhidraContext.passesFilter(func.getName(), filterLower, compiled)) continue;

                functions.add(func);
            }
        }

        result.total = functions.size();

        // Cap at limit
        if (functions.size() > limit) {
            functions = functions.subList(0, limit);
        }

        // Decompile in parallel using the pool
        com.ghidramcp.DecompilerPool pool = ctx.getDecompilerPool();
        if (pool != null && functions.size() > 1) {
            // Submit all to pool, collect in order
            List<Future<DecompileResults>> futures = new ArrayList<>(functions.size());
            for (Function func : functions) {
                futures.add(pool.submit(func, decompileTimeout));
            }
            for (int i = 0; i < functions.size(); i++) {
                Function func = functions.get(i);
                try {
                    DecompileResults dr = futures.get(i).get();
                    result.results.add(buildDecompileResult(func, dr));
                } catch (Exception e) {
                    Throwable cause = e.getCause() != null ? e.getCause() : e;
                    GhidraEngine.BatchDecompileFailure fail = new GhidraEngine.BatchDecompileFailure();
                    fail.address = func.getEntryPoint().toString();
                    fail.name = func.getName();
                    fail.error = cause.getMessage();
                    result.failed.add(fail);
                }
            }
        } else {
            // Sequential fallback
            for (Function func : functions) {
                try {
                    GhidraEngine.DecompileResult dr = this.decompile(func, decompileTimeout);
                    result.results.add(dr);
                } catch (Exception e) {
                    GhidraEngine.BatchDecompileFailure fail = new GhidraEngine.BatchDecompileFailure();
                    fail.address = func.getEntryPoint().toString();
                    fail.name = func.getName();
                    fail.error = e.getMessage();
                    result.failed.add(fail);
                }
            }
        }

        result.decompiled = result.results.size();
        return result;
    }

    // ==================== FUNCTION SUMMARY ====================

    /**
     * Get a comprehensive function summary
     */
    public GhidraEngine.FunctionSummary getFunctionSummary(String address, String name, boolean includeStrings,
                                                           boolean includeXrefs, int maxCalls, int maxCallers) throws Exception {
        Function func = this.getFunction(address, name);
        if (func == null) {
            throw new Exception("Function not found");
        }

        GhidraEngine.FunctionSummary summary = new GhidraEngine.FunctionSummary();
        summary.name = func.getName();
        summary.address = func.getEntryPoint().toString();
        summary.signature = func.getSignature().getPrototypeString();
        summary.size = (int) func.getBody().getNumAddresses();

        // Get calls (functions this function calls)
        summary.calls = new ArrayList<>();
        ReferenceManager refMgr = ctx.getProgram().getReferenceManager();
        FunctionManager funcMgr = ctx.getProgram().getFunctionManager();

        Set<String> calledFuncs = new HashSet<>();
        for (Address bodyAddr : func.getBody().getAddresses(true)) {
            for (Reference ref : refMgr.getReferencesFrom(bodyAddr)) {
                if (ref.getReferenceType().isCall()) {
                    Function callee = funcMgr.getFunctionAt(ref.getToAddress());
                    if (callee != null && !calledFuncs.contains(callee.getName()) && calledFuncs.size() < maxCalls) {
                        calledFuncs.add(callee.getName());
                        summary.calls.add(callee.getName());
                    }
                }
            }
        }

        // Get callers (functions that call this function)
        summary.callers = new ArrayList<>();
        Set<String> callerFuncs = new HashSet<>();
        for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
            if (ref.getReferenceType().isCall()) {
                Function caller = funcMgr.getFunctionContaining(ref.getFromAddress());
                if (caller != null && !callerFuncs.contains(caller.getName()) && callerFuncs.size() < maxCallers) {
                    callerFuncs.add(caller.getName());
                    summary.callers.add(caller.getName());
                }
            }
        }

        // Get strings referenced by this function
        if (includeStrings) {
            summary.strings = new ArrayList<>();
            for (Address bodyAddr : func.getBody().getAddresses(true)) {
                for (Reference ref : refMgr.getReferencesFrom(bodyAddr)) {
                    Data data = ctx.getProgram().getListing().getDataAt(ref.getToAddress());
                    if (data != null && data.hasStringValue()) {
                        String str = (String) data.getValue();
                        if (str != null && !summary.strings.contains(str)) {
                            summary.strings.add(str);
                        }
                    }
                }
            }
        }

        // Get xref counts
        if (includeXrefs) {
            summary.xrefToCount = refMgr.getReferenceCountTo(func.getEntryPoint());
            summary.xrefFromCount = 0;
            for (Address bodyAddr : func.getBody().getAddresses(true)) {
                summary.xrefFromCount += refMgr.getReferenceCountFrom(bodyAddr);
            }
        }

        // Get local variable count
        summary.localVarCount = func.getLocalVariables().length;
        summary.parameterCount = func.getParameterCount();

        return summary;
    }

    // ==================== BASIC BLOCKS ====================

    /**
     * Get basic blocks for a function with control flow information
     */
    public List<GhidraEngine.BasicBlockInfo> getBasicBlocks(String address, String name) throws Exception {
        Function func = this.getFunction(address, name);
        if (func == null) {
            throw new Exception("Function not found");
        }

        List<GhidraEngine.BasicBlockInfo> blocks = new ArrayList<>();
        BasicBlockModel bbModel = new BasicBlockModel(ctx.getProgram());

        CodeBlockIterator blockIter = bbModel.getCodeBlocksContaining(func.getBody(), ctx.getMonitor());
        while (blockIter.hasNext()) {
            CodeBlock block = blockIter.next();

            GhidraEngine.BasicBlockInfo info = new GhidraEngine.BasicBlockInfo();
            info.startAddress = block.getFirstStartAddress().toString();
            info.endAddress = block.getMaxAddress().toString();
            info.size = block.getNumAddresses();

            // Get successors
            info.successors = new ArrayList<>();
            CodeBlockReferenceIterator destIter = block.getDestinations(ctx.getMonitor());
            while (destIter.hasNext()) {
                CodeBlockReference ref = destIter.next();
                info.successors.add(ref.getDestinationAddress().toString());
            }

            // Get predecessors
            info.predecessors = new ArrayList<>();
            CodeBlockReferenceIterator srcIter = block.getSources(ctx.getMonitor());
            while (srcIter.hasNext()) {
                CodeBlockReference ref = srcIter.next();
                info.predecessors.add(ref.getSourceAddress().toString());
            }

            blocks.add(info);
        }

        return blocks;
    }

    // ==================== CALL GRAPH ====================

    /**
     * Get call graph starting from a function
     */
    public GhidraEngine.CallGraphResult getCallGraph(String address, String name, int depth, String direction, int maxNodes) throws Exception {
        Function func = this.getFunction(address, name);
        if (func == null) {
            throw new Exception("Function not found");
        }

        GhidraEngine.CallGraphResult result = new GhidraEngine.CallGraphResult();
        result.rootFunction = func.getName();
        result.rootAddress = func.getEntryPoint().toString();
        result.nodes = new ArrayList<>();
        result.edges = new ArrayList<>();

        Set<String> visited = new HashSet<>();
        buildCallGraph(func, depth, direction, visited, result, maxNodes > 0 ? maxNodes : 500);

        return result;
    }

    private void buildCallGraph(Function func, int depth, String direction, Set<String> visited, GhidraEngine.CallGraphResult result, int maxNodes) {
        String funcKey = func.getEntryPoint().toString();
        if (visited.contains(funcKey) || depth < 0 || result.nodes.size() >= maxNodes) {
            if (result.nodes.size() >= maxNodes) {
                result.truncated = true;
            }
            return;
        }
        visited.add(funcKey);

        // Add this function as a node
        GhidraEngine.CallGraphNode node = new GhidraEngine.CallGraphNode();
        node.name = func.getName();
        node.address = func.getEntryPoint().toString();
        result.nodes.add(node);

        ReferenceManager refMgr = ctx.getProgram().getReferenceManager();
        FunctionManager funcMgr = ctx.getProgram().getFunctionManager();

        // Get outgoing calls (functions this function calls)
        if (direction.equals("out") || direction.equals("both")) {
            Set<String> callees = new HashSet<>();
            for (Address bodyAddr : func.getBody().getAddresses(true)) {
                for (Reference ref : refMgr.getReferencesFrom(bodyAddr)) {
                    if (ref.getReferenceType().isCall()) {
                        Function callee = funcMgr.getFunctionAt(ref.getToAddress());
                        if (callee != null && !callees.contains(callee.getEntryPoint().toString())) {
                            callees.add(callee.getEntryPoint().toString());

                            GhidraEngine.CallGraphEdge edge = new GhidraEngine.CallGraphEdge();
                            edge.from = funcKey;
                            edge.to = callee.getEntryPoint().toString();
                            edge.type = "calls";
                            result.edges.add(edge);

                            if (depth > 0) {
                                buildCallGraph(callee, depth - 1, direction, visited, result, maxNodes);
                            }
                        }
                    }
                }
            }
        }

        // Get incoming calls (functions that call this function)
        if (direction.equals("in") || direction.equals("both")) {
            Set<String> callers = new HashSet<>();
            for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
                if (ref.getReferenceType().isCall()) {
                    Function caller = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (caller != null && !callers.contains(caller.getEntryPoint().toString())) {
                        callers.add(caller.getEntryPoint().toString());

                        GhidraEngine.CallGraphEdge edge = new GhidraEngine.CallGraphEdge();
                        edge.from = caller.getEntryPoint().toString();
                        edge.to = funcKey;
                        edge.type = "called_by";
                        result.edges.add(edge);

                        if (depth > 0) {
                            buildCallGraph(caller, depth - 1, direction, visited, result, maxNodes);
                        }
                    }
                }
            }
        }
    }

    // ==================== CALL PATH ====================

    /**
     * Find a call path between two functions
     */
    public GhidraEngine.CallPathResult findCallPath(String fromSpec, String toSpec, int maxDepth) throws Exception {
        Function fromFunc = this.getFunction(fromSpec, fromSpec);
        Function toFunc = this.getFunction(toSpec, toSpec);

        if (fromFunc == null) {
            throw new Exception("Source function not found: " + fromSpec);
        }
        if (toFunc == null) {
            throw new Exception("Target function not found: " + toSpec);
        }

        GhidraEngine.CallPathResult result = new GhidraEngine.CallPathResult();
        result.from = fromFunc.getName();
        result.to = toFunc.getName();
        result.paths = new ArrayList<>();

        // BFS to find paths
        List<List<String>> paths = findPaths(fromFunc, toFunc, maxDepth);
        result.paths = paths;
        result.found = !paths.isEmpty();

        return result;
    }

    private List<List<String>> findPaths(Function from, Function to, int maxDepth) {
        List<List<String>> allPaths = new ArrayList<>();
        Queue<List<Function>> queue = new LinkedList<>();

        List<Function> startPath = new ArrayList<>();
        startPath.add(from);
        queue.add(startPath);

        ReferenceManager refMgr = ctx.getProgram().getReferenceManager();
        FunctionManager funcMgr = ctx.getProgram().getFunctionManager();

        while (!queue.isEmpty() && allPaths.size() < 10) {
            List<Function> currentPath = queue.poll();
            Function current = currentPath.get(currentPath.size() - 1);

            if (currentPath.size() > maxDepth) {
                continue;
            }

            // Get all functions called by current
            Set<Function> callees = new HashSet<>();
            for (Address bodyAddr : current.getBody().getAddresses(true)) {
                for (Reference ref : refMgr.getReferencesFrom(bodyAddr)) {
                    if (ref.getReferenceType().isCall()) {
                        Function callee = funcMgr.getFunctionAt(ref.getToAddress());
                        if (callee != null) {
                            callees.add(callee);
                        }
                    }
                }
            }

            for (Function callee : callees) {
                if (currentPath.stream().anyMatch(f -> f.getEntryPoint().equals(callee.getEntryPoint()))) {
                    continue; // Avoid cycles
                }

                List<Function> newPath = new ArrayList<>(currentPath);
                newPath.add(callee);

                if (callee.getEntryPoint().equals(to.getEntryPoint())) {
                    // Found a path
                    List<String> pathNames = new ArrayList<>();
                    for (Function f : newPath) {
                        pathNames.add(f.getName());
                    }
                    allPaths.add(pathNames);
                } else if (newPath.size() < maxDepth) {
                    queue.add(newPath);
                }
            }
        }

        return allPaths;
    }

    // ==================== FIND FUNCTIONS MATCHING ====================

    /**
     * Find functions that match compound criteria
     */
    public List<GhidraEngine.FunctionListEntry> findFunctionsMatching(List<String> calls, List<String> notCalls,
                                                                 String referencesString, String inNamespace,
                                                                 int sizeMin, int sizeMax, int limit) {
        // Lightweight entries (name/address/signature/size) — NOT full FunctionInfo: a
        // broad match set with full params+locals (and, since #31, a decompile each) blows
        // the token limit and is slow. Callers get_function_info the few they want.
        List<GhidraEngine.FunctionListEntry> matches = new ArrayList<>();
        FunctionManager funcMgr = ctx.getProgram().getFunctionManager();
        ReferenceManager refMgr = ctx.getProgram().getReferenceManager();

        Iterator<Function> funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext() && matches.size() < limit) {
            Function func = funcIter.next();

            // Filter by namespace
            if (inNamespace != null) {
                Namespace ns = func.getParentNamespace();
                if (ns == null || !ns.getName().equals(inNamespace)) {
                    continue;
                }
            }

            // Filter by size
            int funcSize = (int) func.getBody().getNumAddresses();
            if (sizeMin >= 0 && funcSize < sizeMin) continue;
            if (sizeMax >= 0 && funcSize > sizeMax) continue;

            // Get called functions
            Set<String> calledFuncs = new HashSet<>();
            for (Address bodyAddr : func.getBody().getAddresses(true)) {
                for (Reference ref : refMgr.getReferencesFrom(bodyAddr)) {
                    if (ref.getReferenceType().isCall()) {
                        Function callee = funcMgr.getFunctionAt(ref.getToAddress());
                        if (callee != null) {
                            calledFuncs.add(callee.getName());
                        }
                    }
                }
            }

            // Check calls filter
            if (calls != null && !calls.isEmpty()) {
                boolean allFound = true;
                for (String call : calls) {
                    if (!calledFuncs.contains(call)) {
                        allFound = false;
                        break;
                    }
                }
                if (!allFound) continue;
            }

            // Check notCalls filter
            if (notCalls != null && !notCalls.isEmpty()) {
                boolean anyFound = false;
                for (String notCall : notCalls) {
                    if (calledFuncs.contains(notCall)) {
                        anyFound = true;
                        break;
                    }
                }
                if (anyFound) continue;
            }

            // Check string reference filter
            if (referencesString != null) {
                boolean foundString = false;
                for (Address bodyAddr : func.getBody().getAddresses(true)) {
                    for (Reference ref : refMgr.getReferencesFrom(bodyAddr)) {
                        Data data = ctx.getProgram().getListing().getDataAt(ref.getToAddress());
                        if (data != null && data.hasStringValue()) {
                            String str = (String) data.getValue();
                            if (str != null && str.contains(referencesString)) {
                                foundString = true;
                                break;
                            }
                        }
                    }
                    if (foundString) break;
                }
                if (!foundString) continue;
            }

            matches.add(this.getFunctionListEntry(func));
        }

        return matches;
    }

    // ==================== CREATE / DELETE ====================

    /**
     * Create a function at an address
     */
    public GhidraEngine.FunctionInfo createFunction(String addressStr, String name) throws Exception {
        Address address = ctx.parseAddress(addressStr);
        Program program = ctx.getProgram();

        int txId = program.startTransaction("Create function");
        try {
            Function func = ctx.getFlatApi().createFunction(address, name);
            if (func == null) {
                program.endTransaction(txId, false);
                throw new Exception("Failed to create function at " + addressStr);
            }
            program.endTransaction(txId, true);
            return this.getFunctionInfo(func);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Delete a function
     */
    public void deleteFunction(String addressStr) throws Exception {
        Address address = ctx.parseAddress(addressStr);
        Program program = ctx.getProgram();
        FunctionManager funcMgr = program.getFunctionManager();

        int txId = program.startTransaction("Delete function");
        try {
            Function func = funcMgr.getFunctionAt(address);
            if (func != null) {
                funcMgr.removeFunction(address);
            }
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    // ==================== LINE MAPPINGS ====================

    /**
     * Get line-to-address mappings for a decompiled function.
     * Used for source map generation in reconstructed code.
     */
    public List<GhidraEngine.LineMapping> getLineMappings(String addressStr, String name, int timeout) throws Exception {
        Function func = this.getFunction(addressStr, name);
        if (func == null) {
            throw new Exception("Function not found");
        }

        List<GhidraEngine.LineMapping> mappings = new ArrayList<>();

        DecompileResults results = ctx.getDecompiler().decompileFunction(func, timeout, ctx.getMonitor());
        if (!results.decompileCompleted()) {
            return mappings;
        }

        // Get the Clang token group which contains line/address associations
        ghidra.app.decompiler.ClangTokenGroup tokens = results.getCCodeMarkup();
        if (tokens == null) {
            return mappings;
        }

        // Walk the token tree to extract address associations
        collectLineMappings(tokens, mappings);

        return mappings;
    }

    private void collectLineMappings(ghidra.app.decompiler.ClangNode node, List<GhidraEngine.LineMapping> mappings) {
        if (node instanceof ghidra.app.decompiler.ClangToken) {
            ghidra.app.decompiler.ClangToken token = (ghidra.app.decompiler.ClangToken) node;
            Address minAddr = token.getMinAddress();
            if (minAddr != null) {
                GhidraEngine.LineMapping mapping = new GhidraEngine.LineMapping();
                mapping.line = token.getLineParent() != null ? token.getLineParent().getLineNumber() : 0;
                mapping.address = minAddr.toString();
                mapping.text = token.toString();
                mappings.add(mapping);
            }
        }

        // Recurse into children
        int numChildren = node.numChildren();
        for (int i = 0; i < numChildren; i++) {
            collectLineMappings(node.Child(i), mappings);
        }
    }
}
