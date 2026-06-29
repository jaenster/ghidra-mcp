package com.ghidramcp.operations;

import com.ghidramcp.GhidraContext;
import com.ghidramcp.GhidraEngine;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraState;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import ghidra.app.cmd.function.CreateFunctionCmd;


import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

/**
 * Analysis, search, script execution, undo/redo, export, and variable operations.
 * This is the largest operations class, containing search infrastructure,
 * P-code analysis, data flow tracing, script execution (JS + Python),
 * undo/redo history, stack frame inspection, switch table extraction,
 * function variable rename/retype, re-analysis triggers, and full C export.
 */
public class AnalysisOps {
    private final GhidraContext ctx;

    public AnalysisOps(GhidraContext ctx) {
        this.ctx = ctx;
    }

    // =====================================================================
    //  SEARCH
    // =====================================================================

    /**
     * Unified search across functions, strings, symbols, imports, exports, data, and comments
     */
    public GhidraEngine.SearchResponse search(String filter, String regex, String hexPattern, List<String> types,
                                  boolean caseSensitive, int limit, int offset,
                                  boolean countOnly, boolean includeContext,
                                  String scopeType, String scopeValue,
                                  String scopeStartAddress, String scopeEndAddress,
                                  String functionFilter, String searchMode, String flowType) {
        Program program = ctx.getProgram();
        SearchContext sctx = new SearchContext(offset, limit, countOnly, includeContext);

        // Build a compiled pattern from filter and/or regex for search sub-methods
        // For backward compatibility: if regex is set, compile it; otherwise use filter as substring
        int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
        Pattern compiledRegex = null;
        if (regex != null && !regex.isEmpty()) {
            try {
                compiledRegex = Pattern.compile(regex, flags);
            } catch (Exception e) {
                compiledRegex = Pattern.compile(Pattern.quote(regex), flags);
            }
        } else if (filter != null && !filter.isEmpty()) {
            // For search sub-methods that expect a Pattern, create one from filter as a literal substring
            compiledRegex = Pattern.compile(Pattern.quote(filter), flags);
        }

        // Resolve scope to address range for expensive searches
        AddressSet scopeAddressSet = null;
        if (scopeType != null) {
            scopeAddressSet = resolveScopeToAddressSet(scopeType, scopeValue, scopeStartAddress, scopeEndAddress);
        }

        boolean searchAll = types.contains("all");

        // If no filter/regex specified, match everything (like the old default of ".*")
        if (compiledRegex == null) {
            compiledRegex = Pattern.compile(".*", flags);
        }

        // Search functions
        if (searchAll || types.contains("functions")) {
            searchFunctions(compiledRegex, sctx, scopeAddressSet);
        }

        // Search strings
        if (searchAll || types.contains("strings")) {
            searchStrings(compiledRegex, sctx, scopeAddressSet);
        }

        // Search symbols
        if (searchAll || types.contains("symbols")) {
            searchSymbols(compiledRegex, sctx, scopeAddressSet);
        }

        // Search imports
        if (searchAll || types.contains("imports")) {
            searchImports(compiledRegex, sctx, scopeAddressSet);
        }

        // Search exports
        if (searchAll || types.contains("exports")) {
            searchExports(compiledRegex, sctx, scopeAddressSet);
        }

        // Search data labels
        if (searchAll || types.contains("data")) {
            searchData(compiledRegex, sctx, scopeAddressSet);
        }

        // Search namespaces
        if (searchAll || types.contains("namespaces")) {
            searchNamespaces(compiledRegex, sctx, scopeAddressSet);
        }

        // Search comments
        if (searchAll || types.contains("comments")) {
            searchComments(compiledRegex, sctx, scopeAddressSet);
        }

        // EXPENSIVE search types - NOT included in "all", require explicit opt-in
        if (types.contains("disassembly")) {
            searchDisassembly(compiledRegex, sctx, scopeAddressSet, functionFilter, searchMode, flowType);
        }

        if (types.contains("decompiled")) {
            searchDecompiled(compiledRegex, sctx, scopeAddressSet, functionFilter);
        }

        if (types.contains("bytes")) {
            String bytesPattern = hexPattern != null ? hexPattern : (filter != null ? filter : "");
            if (!bytesPattern.isEmpty()) {
                searchBytes(bytesPattern, sctx, scopeAddressSet);
            }
        }

        return sctx.toResponse();
    }

    // =====================================================================
    //  SEARCH HELPERS
    // =====================================================================

    /**
     * Resolve scope parameters to a Ghidra AddressSet
     */
    private AddressSet resolveScopeToAddressSet(
            String scopeType, String scopeValue, String startAddr, String endAddr) {
        Program program = ctx.getProgram();
        AddressSet addrSet = new AddressSet();

        switch (scopeType) {
            case "function": {
                // Inline getFunction logic (originally in FunctionOps)
                Function func = null;
                if (scopeValue != null) {
                    // Try as address first
                    Address addr = ctx.parseAddress(scopeValue);
                    if (addr != null) {
                        func = program.getFunctionManager().getFunctionAt(addr);
                    }
                    // If not found by address, try by name
                    if (func == null) {
                        Iterator<Function> iter = program.getFunctionManager().getFunctions(true);
                        while (iter.hasNext()) {
                            Function f = iter.next();
                            if (f.getName().equals(scopeValue)) {
                                func = f;
                                break;
                            }
                        }
                    }
                }
                if (func != null) {
                    addrSet.add(func.getBody());
                }
                break;
            }
            case "namespace": {
                Iterator<Function> iter = program.getFunctionManager().getFunctions(true);
                while (iter.hasNext()) {
                    Function func = iter.next();
                    Namespace ns = func.getParentNamespace();
                    if (ns != null && !ns.isGlobal() && ns.getName(true).contains(scopeValue)) {
                        addrSet.add(func.getBody());
                    }
                }
                break;
            }
            case "address_range": {
                if (startAddr != null && endAddr != null) {
                    Address start = ctx.parseAddress(startAddr);
                    Address end = ctx.parseAddress(endAddr);
                    if (start != null && end != null) {
                        addrSet.addRange(start, end);
                    }
                }
                break;
            }
            default:
                // "program" or unknown — return null means use full program
                return null;
        }

        return addrSet.isEmpty() ? null : addrSet;
    }

    /**
     * Search through disassembly instructions matching regex against "MNEMONIC operand1,operand2"
     */
    private void searchDisassembly(Pattern regex, SearchContext sctx,
                                    AddressSet scope, String functionFilter) {
        searchDisassembly(regex, sctx, scope, functionFilter, null, null);
    }

    private void searchDisassembly(Pattern regex, SearchContext sctx,
                                    AddressSet scope, String functionFilter,
                                    String searchMode, String flowType) {
        Program program = ctx.getProgram();
        Listing listing = program.getListing();
        InstructionIterator iter;

        if (scope != null) {
            iter = listing.getInstructions(scope, true);
        } else {
            iter = listing.getInstructions(true);
        }

        Pattern funcFilter = null;
        if (functionFilter != null) {
            try {
                funcFilter = Pattern.compile(functionFilter);
            } catch (Exception e) {
                funcFilter = Pattern.compile(Pattern.quote(functionFilter));
            }
        }

        while (iter.hasNext()) {
            ghidra.program.model.listing.Instruction instr = iter.next();

            // Function name filter
            if (funcFilter != null) {
                Function func = program.getFunctionManager().getFunctionContaining(instr.getAddress());
                if (func == null || !funcFilter.matcher(func.getName()).find()) continue;
            }

            // Flow type pre-filter
            if (flowType != null) {
                ghidra.program.model.symbol.FlowType ft = instr.getFlowType();
                boolean match;
                switch (flowType) {
                    case "call": match = ft.isCall(); break;
                    case "jump": match = ft.isJump(); break;
                    case "conditional_jump": match = ft.isConditional() && ft.isJump(); break;
                    case "unconditional_jump": match = ft.isUnConditional() && ft.isJump(); break;
                    case "terminal": match = ft.isTerminal(); break;
                    default: match = true; break;
                }
                if (!match) continue;
            }

            // Build match text based on search mode
            String matchText;
            String mode = searchMode != null ? searchMode : "regex";
            switch (mode) {
                case "mnemonic":
                    matchText = instr.getMnemonicString();
                    break;
                case "operand": {
                    StringBuilder ops = new StringBuilder();
                    for (int i = 0; i < instr.getNumOperands(); i++) {
                        if (i > 0) ops.append(",");
                        ops.append(instr.getDefaultOperandRepresentation(i));
                    }
                    matchText = ops.toString();
                    break;
                }
                default:
                    matchText = instr.toString();
                    break;
            }

            if (regex.matcher(matchText).find()) {
                GhidraEngine.SearchResult result = new GhidraEngine.SearchResult();
                result.type = "instruction";
                result.name = instr.toString();
                result.address = instr.getAddress().toString();

                if (sctx.includeContext && sctx.willCollect()) {
                    JsonObject context = new JsonObject();
                    // Encode bytes as hex
                    try {
                        byte[] bytes = instr.getBytes();
                        StringBuilder hexBytes = new StringBuilder();
                        for (byte b : bytes) {
                            hexBytes.append(String.format("%02x ", b));
                        }
                        context.addProperty("bytes", hexBytes.toString().trim());
                    } catch (Exception e) {
                        // Ignore memory access errors
                    }

                    Function func = program.getFunctionManager().getFunctionContaining(instr.getAddress());
                    if (func != null) {
                        context.addProperty("inFunction", func.getName());
                    }
                    result.context = context;
                }

                sctx.addMatch(result);
            }
        }
    }

    /**
     * Search for hex byte patterns with ?? wildcards.
     * Pattern format: "55 8B EC" or "55 ?? EC"
     */
    private void searchBytes(String patternStr, SearchContext sctx,
                              AddressSet scope) {
        Program program = ctx.getProgram();
        TaskMonitor monitor = ctx.getMonitor();

        // Parse hex pattern with ?? wildcards
        String[] tokens = patternStr.trim().split("\\s+");
        byte[] values = new byte[tokens.length];
        byte[] masks = new byte[tokens.length];

        for (int i = 0; i < tokens.length; i++) {
            if (tokens[i].equals("??")) {
                values[i] = 0;
                masks[i] = 0; // Don't care
            } else {
                try {
                    values[i] = (byte) Integer.parseInt(tokens[i], 16);
                    masks[i] = (byte) 0xFF;
                } catch (NumberFormatException e) {
                    // Invalid hex — skip this search
                    return;
                }
            }
        }

        Memory memory = program.getMemory();
        Address start;
        Address end;

        if (scope != null) {
            start = scope.getMinAddress();
            end = scope.getMaxAddress();
        } else {
            start = program.getMinAddress();
            end = program.getMaxAddress();
        }

        Address found = start;
        while (found != null) {
            found = memory.findBytes(found, end, values, masks, true, monitor);
            if (found == null) break;

            // Build matched hex string
            StringBuilder matchedHex = new StringBuilder();
            try {
                byte[] matchedBytes = new byte[values.length];
                memory.getBytes(found, matchedBytes);
                for (byte b : matchedBytes) {
                    matchedHex.append(String.format("%02X ", b));
                }
            } catch (Exception e) {
                matchedHex.append("(read error)");
            }

            GhidraEngine.SearchResult result = new GhidraEngine.SearchResult();
            result.type = "bytes";
            result.name = matchedHex.toString().trim();
            result.address = found.toString();

            if (sctx.includeContext && sctx.willCollect()) {
                JsonObject context = new JsonObject();
                Function func = program.getFunctionManager().getFunctionContaining(found);
                if (func != null) {
                    context.addProperty("inFunction", func.getName());
                }
                // Include surrounding bytes as hex dump
                try {
                    Address dumpStart = found.subtract(Math.min(found.getOffset() - program.getMinAddress().getOffset(), 8));
                    byte[] surrounding = new byte[values.length + 16];
                    int read = memory.getBytes(dumpStart, surrounding);
                    StringBuilder dump = new StringBuilder();
                    for (int i = 0; i < read; i++) {
                        dump.append(String.format("%02X ", surrounding[i]));
                    }
                    context.addProperty("surroundingBytes", dump.toString().trim());
                } catch (Exception e) {
                    // Ignore dump errors
                }
                result.context = context;
            }

            sctx.addMatch(result);

            // Advance past this match
            try {
                found = found.add(1);
            } catch (Exception e) {
                break; // Address overflow
            }
        }
    }

    /**
     * Search through decompiled pseudocode. One result per function (first match).
     * Hard cap: 200 functions without scope.
     */
    private void searchDecompiled(Pattern regex, SearchContext sctx,
                                   AddressSet scope, String functionFilter) {
        Program program = ctx.getProgram();
        DecompInterface decompiler = ctx.getDecompiler();
        TaskMonitor monitor = ctx.getMonitor();
        com.ghidramcp.DecompilerPool pool = ctx.getDecompilerPool();

        FunctionManager fm = program.getFunctionManager();
        Iterator<Function> iter;

        if (scope != null) {
            iter = fm.getFunctions(scope, true);
        } else {
            iter = fm.getFunctions(true);
        }

        Pattern funcFilter = null;
        if (functionFilter != null) {
            try {
                funcFilter = Pattern.compile(functionFilter);
            } catch (Exception e) {
                funcFilter = Pattern.compile(Pattern.quote(functionFilter));
            }
        }

        int hardCap = (scope != null || funcFilter != null) ? Integer.MAX_VALUE : 200;

        // Collect candidate functions
        List<Function> candidates = new ArrayList<>();
        while (iter.hasNext() && candidates.size() < hardCap) {
            Function func = iter.next();
            if (funcFilter != null && !funcFilter.matcher(func.getName()).find()) continue;
            candidates.add(func);
        }

        if (pool != null && candidates.size() > 1) {
            // Parallel search: submit in batches
            int batchSize = pool.getPoolSize() * 4;
            for (int start = 0; start < candidates.size() && !sctx.isFull(); start += batchSize) {
                int end = Math.min(start + batchSize, candidates.size());
                List<Function> batch = candidates.subList(start, end);
                List<Future<DecompileResults>> futures = new ArrayList<>(batch.size());

                for (Function func : batch) {
                    futures.add(pool.submit(func, 10));
                }

                for (int i = 0; i < batch.size(); i++) {
                    Function func = batch.get(i);
                    try {
                        DecompileResults results = futures.get(i).get();
                        if (!results.decompileCompleted()) continue;
                        String code = results.getDecompiledFunction().getC();
                        if (code == null) continue;
                        processSearchMatch(func, code, regex, sctx);
                    } catch (Exception e) {
                        // Skip functions that fail to decompile
                    }
                }
            }
        } else {
            // Sequential fallback
            for (Function func : candidates) {
                try {
                    DecompileResults results = decompiler.decompileFunction(func, 10, monitor);
                    if (!results.decompileCompleted()) continue;
                    String code = results.getDecompiledFunction().getC();
                    if (code == null) continue;
                    processSearchMatch(func, code, regex, sctx);
                } catch (Exception e) {
                    // Skip functions that fail to decompile
                }
            }
        }
    }

    /**
     * Check decompiled code for regex match and add to search context.
     */
    private void processSearchMatch(Function func, String code, Pattern regex,
                                     SearchContext sctx) {
        String[] lines = code.split("\n");
        for (int lineNum = 0; lineNum < lines.length; lineNum++) {
            if (regex.matcher(lines[lineNum]).find()) {
                GhidraEngine.SearchResult result = new GhidraEngine.SearchResult();
                result.type = "decompiled";
                result.name = func.getName();
                result.address = func.getEntryPoint().toString();

                if (sctx.includeContext && sctx.willCollect()) {
                    JsonObject context = new JsonObject();
                    context.addProperty("line", lineNum + 1);
                    context.addProperty("matchedLine", lines[lineNum].trim());
                    context.addProperty("signature", func.getSignature().getPrototypeString());
                    result.context = context;
                }

                sctx.addMatch(result);
                break; // One result per function
            }
        }
    }

    private void searchFunctions(Pattern regex, SearchContext sctx, AddressSet scope) {
        Program program = ctx.getProgram();
        FunctionManager fm = program.getFunctionManager();
        Iterator<Function> iter = scope != null ? fm.getFunctions(scope, true) : fm.getFunctions(true);

        while (iter.hasNext()) {
            Function func = iter.next();
            String name = func.getName();

            if (regex.matcher(name).find()) {
                GhidraEngine.SearchResult result = new GhidraEngine.SearchResult();
                result.type = "function";
                result.name = name;
                result.address = func.getEntryPoint().toString();

                // Only build expensive context when this result will land in the page
                if (sctx.includeContext && sctx.willCollect()) {
                    JsonObject context = new JsonObject();
                    context.addProperty("signature", func.getSignature().getPrototypeString());
                    context.addProperty("size", (int) func.getBody().getNumAddresses());

                    int callCount = program.getReferenceManager().getReferenceCountTo(func.getEntryPoint());
                    context.addProperty("callCount", callCount);

                    JsonArray callers = new JsonArray();
                    int callerCount = 0;
                    for (Reference ref : program.getReferenceManager().getReferencesTo(func.getEntryPoint())) {
                        if (ref.getReferenceType().isCall() && callerCount < 5) {
                            Function caller = fm.getFunctionContaining(ref.getFromAddress());
                            if (caller != null) {
                                callers.add(caller.getName());
                                callerCount++;
                            }
                        }
                    }
                    context.add("calledBy", callers);
                    result.context = context;
                }

                sctx.addMatch(result);
            }
        }
    }

    private void searchStrings(Pattern regex, SearchContext sctx, AddressSet scope) {
        Program program = ctx.getProgram();
        DataIterator iter = program.getListing().getDefinedData(true);

        while (iter.hasNext()) {
            Data data = iter.next();

            if (scope != null && !scope.contains(data.getAddress())) continue;
            if (!data.hasStringValue()) continue;

            String value = (String) data.getValue();
            if (value == null) continue;

            if (regex.matcher(value).find()) {
                GhidraEngine.SearchResult result = new GhidraEngine.SearchResult();
                result.type = "string";
                result.name = value;
                result.address = data.getAddress().toString();

                if (sctx.includeContext && sctx.willCollect()) {
                    JsonObject context = new JsonObject();
                    context.addProperty("fullValue", value);
                    context.addProperty("length", value.length());

                    int xrefCount = program.getReferenceManager().getReferenceCountTo(data.getAddress());
                    context.addProperty("xrefCount", xrefCount);

                    Function func = program.getFunctionManager().getFunctionContaining(data.getAddress());
                    if (func != null) {
                        context.addProperty("inFunction", func.getName());
                    }

                    result.context = context;
                }

                sctx.addMatch(result);
            }
        }
    }

    private void searchSymbols(Pattern regex, SearchContext sctx, AddressSet scope) {
        Program program = ctx.getProgram();
        SymbolTable symTable = program.getSymbolTable();

        for (Symbol sym : symTable.getAllSymbols(true)) {
            if (scope != null && !scope.contains(sym.getAddress())) continue;
            String name = sym.getName();

            if (regex.matcher(name).find()) {
                GhidraEngine.SearchResult result = new GhidraEngine.SearchResult();
                result.type = "symbol";
                result.name = name;
                result.address = sym.getAddress().toString();

                if (sctx.includeContext && sctx.willCollect()) {
                    JsonObject context = new JsonObject();
                    context.addProperty("symbolType", sym.getSymbolType().toString());

                    Namespace ns = sym.getParentNamespace();
                    if (ns != null && !ns.isGlobal()) {
                        context.addProperty("namespace", ns.getName());
                    }

                    context.addProperty("isPrimary", sym.isPrimary());
                    context.addProperty("isExternal", sym.isExternal());

                    result.context = context;
                }

                sctx.addMatch(result);
            }
        }
    }

    private void searchImports(Pattern regex, SearchContext sctx, AddressSet scope) {
        Program program = ctx.getProgram();
        SymbolTable symTable = program.getSymbolTable();

        for (Symbol sym : symTable.getExternalSymbols()) {
            if (scope != null && !scope.contains(sym.getAddress())) continue;
            String name = sym.getName();

            if (regex.matcher(name).find()) {
                GhidraEngine.SearchResult result = new GhidraEngine.SearchResult();
                result.type = "import";
                result.name = name;
                result.address = sym.getAddress().toString();

                if (sctx.includeContext && sctx.willCollect()) {
                    JsonObject context = new JsonObject();

                    ExternalLocation extLoc = program.getExternalManager().getExternalLocation(sym);
                    if (extLoc != null) {
                        context.addProperty("library", extLoc.getLibraryName());
                    }

                    result.context = context;
                }

                sctx.addMatch(result);
            }
        }
    }

    private void searchExports(Pattern regex, SearchContext sctx, AddressSet scope) {
        Program program = ctx.getProgram();
        SymbolTable symTable = program.getSymbolTable();

        for (Symbol sym : symTable.getAllSymbols(true)) {
            if (!sym.isExternalEntryPoint()) continue;
            if (scope != null && !scope.contains(sym.getAddress())) continue;

            String name = sym.getName();

            if (regex.matcher(name).find()) {
                GhidraEngine.SearchResult result = new GhidraEngine.SearchResult();
                result.type = "export";
                result.name = name;
                result.address = sym.getAddress().toString();

                if (sctx.includeContext && sctx.willCollect()) {
                    JsonObject context = new JsonObject();
                    context.addProperty("symbolType", sym.getSymbolType().toString());
                    result.context = context;
                }

                sctx.addMatch(result);
            }
        }
    }

    private void searchData(Pattern regex, SearchContext sctx, AddressSet scope) {
        Program program = ctx.getProgram();
        DataIterator iter = program.getListing().getDefinedData(true);

        while (iter.hasNext()) {
            Data data = iter.next();

            if (scope != null && !scope.contains(data.getAddress())) continue;
            // Skip strings - they're handled separately
            if (data.hasStringValue()) continue;

            // Get the label/name for this data
            Symbol sym = program.getSymbolTable().getPrimarySymbol(data.getAddress());
            if (sym == null) continue;

            String name = sym.getName();

            if (regex.matcher(name).find()) {
                GhidraEngine.SearchResult result = new GhidraEngine.SearchResult();
                result.type = "data";
                result.name = name;
                result.address = data.getAddress().toString();

                if (sctx.includeContext && sctx.willCollect()) {
                    JsonObject context = new JsonObject();
                    context.addProperty("dataType", data.getDataType().getName());
                    context.addProperty("size", data.getLength());

                    result.context = context;
                }

                sctx.addMatch(result);
            }
        }
    }

    private void searchNamespaces(Pattern regex, SearchContext sctx, AddressSet scope) {
        Program program = ctx.getProgram();
        SymbolTable symTable = program.getSymbolTable();

        for (Symbol sym : symTable.getAllSymbols(true)) {
            if (sym.getSymbolType() != SymbolType.NAMESPACE &&
                sym.getSymbolType() != SymbolType.CLASS) continue;
            if (scope != null && !scope.contains(sym.getAddress())) continue;

            String name = sym.getName();

            if (regex.matcher(name).find()) {
                GhidraEngine.SearchResult result = new GhidraEngine.SearchResult();
                result.type = "namespace";
                result.name = name;
                result.address = sym.getAddress().toString();

                if (sctx.includeContext && sctx.willCollect()) {
                    JsonObject context = new JsonObject();
                    context.addProperty("symbolType", sym.getSymbolType().toString());

                    Namespace parent = sym.getParentNamespace();
                    if (parent != null && !parent.isGlobal()) {
                        context.addProperty("parentNamespace", parent.getName());
                    }

                    result.context = context;
                }

                sctx.addMatch(result);
            }
        }
    }

    private void searchComments(Pattern regex, SearchContext sctx, AddressSet scope) {
        Program program = ctx.getProgram();
        Listing listing = program.getListing();
        int[] commentTypes = {
            CodeUnit.EOL_COMMENT,
            CodeUnit.PRE_COMMENT,
            CodeUnit.POST_COMMENT,
            CodeUnit.PLATE_COMMENT,
            CodeUnit.REPEATABLE_COMMENT
        };
        String[] commentTypeNames = {"EOL", "PRE", "POST", "PLATE", "REPEATABLE"};

        AddressIterator addrIter = scope != null
            ? listing.getCommentAddressIterator(scope, true)
            : listing.getCommentAddressIterator(program.getMemory(), true);

        while (addrIter.hasNext()) {
            Address addr = addrIter.next();
            CodeUnit cu = listing.getCodeUnitAt(addr);
            if (cu == null) continue;

            for (int i = 0; i < commentTypes.length; i++) {
                String comment = cu.getComment(commentTypes[i]);
                if (comment != null && regex.matcher(comment).find()) {
                    GhidraEngine.SearchResult result = new GhidraEngine.SearchResult();
                    result.type = "comment";
                    result.name = comment;
                    result.address = addr.toString();

                    if (sctx.includeContext && sctx.willCollect()) {
                        JsonObject context = new JsonObject();
                        context.addProperty("commentType", commentTypeNames[i]);

                        Function func = program.getFunctionManager().getFunctionContaining(addr);
                        if (func != null) {
                            context.addProperty("inFunction", func.getName());
                        }

                        result.context = context;
                    }

                    sctx.addMatch(result);
                    break; // Only add once per address even if multiple comment types match
                }
            }
        }
    }

    /**
     * Tracks pagination state across multiple search type passes.
     * Each searchXxx method calls addMatch() for every match found.
     * The context handles offset skipping, limit capping, and total counting.
     */
    static class SearchContext {
        final List<GhidraEngine.SearchResult> results = new ArrayList<>();
        final int offset;
        final int limit;
        final boolean countOnly;
        final boolean includeContext;
        int totalMatches = 0;
        int skipped = 0;

        SearchContext(int offset, int limit, boolean countOnly, boolean includeContext) {
            this.offset = offset;
            this.limit = limit;
            this.countOnly = countOnly;
            this.includeContext = includeContext;
        }

        /** Whether the result page is full — use for early termination when countOnly is false. */
        boolean isFull() {
            return !countOnly && results.size() >= limit;
        }

        /** Whether the next match will actually land in the result page. */
        boolean willCollect() {
            return !countOnly && skipped >= offset && results.size() < limit;
        }

        /**
         * Record a match. Always increments totalMatches.
         * Only adds to results if we're past offset and under limit and not countOnly.
         */
        void addMatch(GhidraEngine.SearchResult result) {
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

        GhidraEngine.SearchResponse toResponse() {
            GhidraEngine.SearchResponse resp = new GhidraEngine.SearchResponse();
            resp.results = results;
            resp.total = totalMatches;
            resp.hasMore = !countOnly && totalMatches > offset + results.size();
            return resp;
        }
    }

    // =====================================================================
    //  ANALYSIS HINTS
    // =====================================================================

    /**
     * Get analysis hints for an address/function
     */
    public GhidraEngine.AnalysisHints getAnalysisHints(String address, String functionName) throws Exception {
        Program program = ctx.getProgram();

        GhidraEngine.AnalysisHints hints = new GhidraEngine.AnalysisHints();
        hints.hints = new ArrayList<>();

        Function func = null;
        if (functionName != null) {
            // Find function by name
            Iterator<Function> iter = program.getFunctionManager().getFunctions(true);
            while (iter.hasNext()) {
                Function f = iter.next();
                if (f.getName().equals(functionName)) {
                    func = f;
                    break;
                }
            }
        } else if (address != null) {
            func = program.getFunctionManager().getFunctionContaining(ctx.parseAddress(address));
        }

        if (func != null) {
            // Check for potential issues
            hints.functionName = func.getName();
            hints.address = func.getEntryPoint().toString();

            // Check if function has undefined behavior patterns
            if (func.getName().startsWith("FUN_")) {
                hints.hints.add("Function has auto-generated name - consider renaming based on behavior");
            }

            // Check parameter count
            if (func.getParameterCount() == 0) {
                hints.hints.add("Function has no parameters - may need signature analysis");
            }

            // Check for untyped parameters
            for (Parameter param : func.getParameters()) {
                if (param.getDataType() instanceof Undefined) {
                    hints.hints.add("Parameter '" + param.getName() + "' has undefined type");
                }
            }

            // Check calling convention
            if (func.getCallingConventionName().equals("unknown")) {
                hints.hints.add("Unknown calling convention - may affect parameter passing");
            }

            // Check if function is a thunk
            if (func.isThunk()) {
                hints.hints.add("Function is a thunk to: " + func.getThunkedFunction(true).getName());
            }

            // Check for stack depth issues
            if (func.getStackFrame().getFrameSize() > 0x1000) {
                hints.hints.add("Large stack frame (" + func.getStackFrame().getFrameSize() + " bytes) - may indicate buffer");
            }
        }

        return hints;
    }

    // =====================================================================
    //  DATA FLOW TRACING
    // =====================================================================

    /**
     * Trace data flow from an address
     */
    public GhidraEngine.DataFlowResult traceDataFlow(String fromStr, int depth, boolean includeCalls) throws Exception {
        Program program = ctx.getProgram();
        DecompInterface decompiler = ctx.getDecompiler();
        TaskMonitor monitor = ctx.getMonitor();

        Address fromAddr = ctx.parseAddress(fromStr);

        GhidraEngine.DataFlowResult result = new GhidraEngine.DataFlowResult();
        result.from = fromStr;
        result.flows = new ArrayList<>();

        // Use decompiler for data flow analysis
        Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
        if (func == null) {
            throw new Exception("No function at address: " + fromStr);
        }

        DecompileResults decompResults = decompiler.decompileFunction(func, 30, monitor);
        if (decompResults.decompileCompleted()) {
            HighFunction hfunc = decompResults.getHighFunction();
            if (hfunc != null) {
                // Find varnodes at the target address
                Iterator<PcodeOpAST> pcodeIter = hfunc.getPcodeOps();
                while (pcodeIter.hasNext()) {
                    PcodeOpAST op = pcodeIter.next();
                    if (op.getSeqnum().getTarget().equals(fromAddr)) {
                        // Trace the output varnode
                        if (op.getOutput() != null) {
                            traceVarnodeFlow(op.getOutput(), hfunc, result.flows, depth, new HashSet<>());
                        }
                    }
                }
            }
        }

        return result;
    }

    private void traceVarnodeFlow(Varnode vn, HighFunction hfunc, List<GhidraEngine.DataFlowNode> flows,
                                   int depth, Set<String> visited) {
        if (depth <= 0 || vn == null) return;

        String vnKey = vn.toString();
        if (visited.contains(vnKey)) return;
        visited.add(vnKey);

        GhidraEngine.DataFlowNode node = new GhidraEngine.DataFlowNode();
        node.address = vn.getAddress() != null ? vn.getAddress().toString() : "const";
        node.description = vn.toString();

        // Find uses of this varnode
        node.uses = new ArrayList<>();
        Iterator<PcodeOpAST> iter = hfunc.getPcodeOps();
        while (iter.hasNext()) {
            PcodeOpAST op = iter.next();
            for (int i = 0; i < op.getNumInputs(); i++) {
                if (op.getInput(i).equals(vn)) {
                    node.uses.add(op.getSeqnum().getTarget() + ": " + op.getMnemonic());

                    // Recursively trace the output
                    if (op.getOutput() != null && depth > 1) {
                        traceVarnodeFlow(op.getOutput(), hfunc, flows, depth - 1, visited);
                    }
                }
            }
        }

        if (!node.uses.isEmpty()) {
            flows.add(node);
        }
    }

    // =====================================================================
    //  P-CODE
    // =====================================================================

    /**
     * Get P-Code for a function
     */
    private GhidraEngine.PcodeVarnode toVarnode(Varnode vn) {
        if (vn == null) return null;
        GhidraEngine.PcodeVarnode result = new GhidraEngine.PcodeVarnode();
        result.space = vn.getAddress().getAddressSpace().getName();
        result.offset = vn.getOffset();
        result.size = vn.getSize();
        return result;
    }

    private GhidraEngine.PcodeVarnode varnodeFromStorage(VariableStorage storage) {
        if (storage == null || storage.getVarnodes().length == 0) return null;
        return toVarnode(storage.getVarnodes()[0]);
    }

    public GhidraEngine.PcodeResult getPcode(String address, String name, boolean highLevel) throws Exception {
        Program program = ctx.getProgram();
        DecompInterface decompiler = ctx.getDecompiler();
        TaskMonitor monitor = ctx.getMonitor();

        Function func = getFunction(address, name);
        if (func == null) {
            throw new Exception("Function not found");
        }

        GhidraEngine.PcodeResult result = new GhidraEngine.PcodeResult();
        result.functionName = func.getName();
        result.address = func.getEntryPoint().toString();
        result.signature = func.getPrototypeString(false, false);
        result.callingConvention = func.getCallingConventionName();
        result.operations = new ArrayList<>();

        if (highLevel) {
            DecompileResults decompResults = decompiler.decompileFunction(func, 30, monitor);
            if (decompResults.decompileCompleted()) {
                HighFunction hfunc = decompResults.getHighFunction();
                if (hfunc != null) {
                    // Build block index map from decompiler's basic blocks
                    java.util.ArrayList<PcodeBlockBasic> blockList = hfunc.getBasicBlocks();
                    java.util.Map<PcodeBlock, Integer> blockIndexMap = new java.util.HashMap<>();
                    for (int i = 0; i < blockList.size(); i++) {
                        blockIndexMap.put(blockList.get(i), i);
                    }

                    // Serialize block graph with successor edges
                    result.blocks = new ArrayList<>();
                    for (int i = 0; i < blockList.size(); i++) {
                        PcodeBlockBasic bb = blockList.get(i);
                        GhidraEngine.PcodeBlockInfo bi = new GhidraEngine.PcodeBlockInfo();
                        bi.index = i;
                        bi.successors = new ArrayList<>();
                        for (int j = 0; j < bb.getOutSize(); j++) {
                            Integer succIdx = blockIndexMap.get(bb.getOut(j));
                            if (succIdx != null) {
                                bi.successors.add(succIdx);
                            }
                        }
                        result.blocks.add(bi);
                    }

                    Iterator<PcodeOpAST> iter = hfunc.getPcodeOps();
                    int seqCounter = 0;
                    while (iter.hasNext()) {
                        PcodeOpAST op = iter.next();
                        GhidraEngine.PcodeOp pcodeOp = new GhidraEngine.PcodeOp();
                        pcodeOp.address = op.getSeqnum().getTarget().toString();
                        pcodeOp.seqNum = seqCounter++;
                        pcodeOp.mnemonic = op.getMnemonic();
                        pcodeOp.output = toVarnode(op.getOutput());
                        pcodeOp.inputs = new ArrayList<>();
                        for (int i = 0; i < op.getNumInputs(); i++) {
                            pcodeOp.inputs.add(toVarnode(op.getInput(i)));
                        }
                        // Tag each op with its decompiler block index
                        PcodeBlock parent = op.getParent();
                        if (parent != null) {
                            Integer idx = blockIndexMap.get(parent);
                            pcodeOp.blockIndex = (idx != null) ? idx : -1;
                        }
                        result.operations.add(pcodeOp);
                    }

                    // Build symbol table from HighFunction
                    result.symbols = new ArrayList<>();
                    LocalSymbolMap lsm = hfunc.getLocalSymbolMap();
                    Iterator<HighSymbol> symIter = lsm.getSymbols();
                    while (symIter.hasNext()) {
                        HighSymbol sym = symIter.next();
                        if (sym == null) continue;
                        GhidraEngine.SymbolEntry entry = new GhidraEngine.SymbolEntry();
                        entry.name = sym.getName();
                        entry.dataType = sym.getDataType() != null ? sym.getDataType().getDisplayName() : "undefined";
                        entry.storage = varnodeFromStorage(sym.getStorage());
                        entry.category = sym.isParameter() ? "param" : "local";
                        entry.paramIndex = sym.getCategoryIndex();
                        result.symbols.add(entry);
                    }

                    // Add global references
                    Iterator<PcodeOpAST> globalIter = hfunc.getPcodeOps();
                    java.util.Set<Long> seenGlobals = new java.util.HashSet<>();
                    while (globalIter.hasNext()) {
                        PcodeOpAST op = globalIter.next();
                        for (int i = 0; i < op.getNumInputs(); i++) {
                            Varnode input = op.getInput(i);
                            if (input != null && input.getAddress().getAddressSpace().getName().equals("ram")) {
                                long addr = input.getOffset();
                                if (!seenGlobals.contains(addr)) {
                                    seenGlobals.add(addr);
                                    Symbol globalSym = program.getSymbolTable().getPrimarySymbol(
                                        program.getAddressFactory().getDefaultAddressSpace().getAddress(addr));
                                    if (globalSym != null && !globalSym.getName().startsWith("DAT_")) {
                                        GhidraEngine.SymbolEntry entry = new GhidraEngine.SymbolEntry();
                                        entry.name = globalSym.getName();
                                        DataType dt = null;
                                        Data data = program.getListing().getDataAt(globalSym.getAddress());
                                        if (data != null) dt = data.getDataType();
                                        entry.dataType = dt != null ? dt.getDisplayName() : "undefined";
                                        entry.storage = toVarnode(input);
                                        entry.category = "global";
                                        entry.paramIndex = -1;
                                        result.symbols.add(entry);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Raw P-code from instructions — no symbol table
            Listing listing = program.getListing();
            int seqCounter = 0;
            for (Address bodyAddr : func.getBody().getAddresses(true)) {
                Instruction instr = listing.getInstructionAt(bodyAddr);
                if (instr != null) {
                    ghidra.program.model.pcode.PcodeOp[] pcode = instr.getPcode();
                    for (ghidra.program.model.pcode.PcodeOp op : pcode) {
                        GhidraEngine.PcodeOp pcodeOp = new GhidraEngine.PcodeOp();
                        pcodeOp.address = instr.getAddress().toString();
                        pcodeOp.seqNum = seqCounter++;
                        pcodeOp.mnemonic = op.getMnemonic();
                        pcodeOp.output = toVarnode(op.getOutput());
                        pcodeOp.inputs = new ArrayList<>();
                        for (int i = 0; i < op.getNumInputs(); i++) {
                            pcodeOp.inputs.add(toVarnode(op.getInput(i)));
                        }
                        result.operations.add(pcodeOp);
                    }
                }
            }
            result.symbols = null;
        }

        return result;
    }

    // =====================================================================
    //  STACK FRAME
    // =====================================================================

    /**
     * Get stack frame layout for a function
     */
    public GhidraEngine.StackFrameResult getStackFrame(String address, String name) throws Exception {
        Function func = getFunction(address, name);
        if (func == null) {
            throw new Exception("Function not found");
        }

        ghidra.program.model.listing.StackFrame frame = func.getStackFrame();

        GhidraEngine.StackFrameResult result = new GhidraEngine.StackFrameResult();
        result.frameSize = frame.getFrameSize();
        result.localSize = frame.getLocalSize();
        result.parameterSize = frame.getParameterSize();
        result.returnAddrOffset = frame.getReturnAddressOffset();
        result.variables = new ArrayList<>();

        for (Variable var : frame.getStackVariables()) {
            GhidraEngine.StackVariableInfo svi = new GhidraEngine.StackVariableInfo();
            svi.offset = var.getStackOffset();
            svi.name = var.getName();
            svi.dataType = var.getDataType().getName();
            svi.size = var.getLength();
            svi.comment = var.getComment();
            svi.isParameter = var.isStackVariable() && var.getStackOffset() >= 0;
            result.variables.add(svi);
        }

        // Sort by offset
        result.variables.sort(Comparator.comparingInt(v -> v.offset));

        return result;
    }

    // =====================================================================
    //  SWITCH TABLE
    // =====================================================================

    /**
     * Get switch/jump table at an address
     */
    public GhidraEngine.SwitchTableResult getSwitchTable(String addressStr) throws Exception {
        Program program = ctx.getProgram();
        DecompInterface decompiler = ctx.getDecompiler();
        TaskMonitor monitor = ctx.getMonitor();

        Address addr = ctx.parseAddress(addressStr);

        // Find the function containing this address
        Function func = program.getFunctionManager().getFunctionContaining(addr);
        if (func == null) {
            throw new Exception("No function found containing address " + addressStr);
        }

        // Decompile the function to get jump tables
        DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
        if (results == null || !results.decompileCompleted()) {
            throw new Exception("Decompilation failed for function at " + func.getEntryPoint());
        }

        HighFunction highFunc = results.getHighFunction();
        if (highFunc == null) {
            throw new Exception("Failed to get high function");
        }

        JumpTable[] jumpTables = highFunc.getJumpTables();
        if (jumpTables == null || jumpTables.length == 0) {
            throw new Exception("No jump tables found in function " + func.getName());
        }

        // Find the matching jump table
        JumpTable matchingTable = null;
        for (JumpTable jt : jumpTables) {
            if (jt.getSwitchAddress().equals(addr)) {
                matchingTable = jt;
                break;
            }
        }

        // If no exact match, return the first one (or closest)
        if (matchingTable == null) {
            // Try finding by containing address
            for (JumpTable jt : jumpTables) {
                matchingTable = jt; // Take the first one
                break;
            }
        }

        if (matchingTable == null) {
            throw new Exception("No jump table found at address " + addressStr);
        }

        GhidraEngine.SwitchTableResult result = new GhidraEngine.SwitchTableResult();
        result.switchAddress = matchingTable.getSwitchAddress().toString();
        result.cases = new ArrayList<>();

        Address[] caseAddresses = matchingTable.getCases();
        result.numCases = caseAddresses.length;

        for (int i = 0; i < caseAddresses.length; i++) {
            GhidraEngine.SwitchCase sc = new GhidraEngine.SwitchCase();
            sc.value = i; // Default sequential index
            sc.targetAddress = caseAddresses[i].toString();

            // Try to get a label at the target
            Symbol sym = program.getSymbolTable().getPrimarySymbol(caseAddresses[i]);
            if (sym != null && !sym.isDynamic()) {
                sc.targetLabel = sym.getName();
            }

            result.cases.add(sc);
        }

        // Default case address (if available)
        // Ghidra may store the default as a separate case
        // For now, we note that JumpTable doesn't always separate default

        return result;
    }

    /**
     * Override switch/jump table at an address with explicit case destinations.
     * Removes existing COMPUTED_JUMP refs and adds new ones for each case address.
     */
    public GhidraEngine.SwitchOverrideResult setSwitchOverride(String addressStr, List<String> caseAddressStrs) throws Exception {
        Program program = ctx.getProgram();
        TaskMonitor monitor = ctx.getMonitor();

        Address branchAddr = ctx.parseAddress(addressStr);

        // Verify there's an instruction at the address
        Instruction instr = program.getListing().getInstructionAt(branchAddr);
        if (instr == null) {
            throw new Exception("No instruction found at address " + addressStr);
        }

        // Find containing function
        Function func = program.getFunctionManager().getFunctionContaining(branchAddr);
        if (func == null) {
            throw new Exception("No function found containing address " + addressStr);
        }

        // Parse case addresses
        List<Address> caseAddrs = new ArrayList<>();
        for (String cas : caseAddressStrs) {
            caseAddrs.add(ctx.parseAddress(cas));
        }

        int txId = program.startTransaction("Set switch override at " + addressStr);
        try {
            // Remove existing COMPUTED_JUMP references from this instruction
            for (Reference ref : instr.getReferencesFrom()) {
                if (ref.getReferenceType() == RefType.COMPUTED_JUMP) {
                    program.getReferenceManager().delete(ref);
                }
            }

            // Add COMPUTED_JUMP refs for each case address
            for (Address dest : caseAddrs) {
                program.getReferenceManager().addMemoryReference(
                    branchAddr, dest, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0
                );
            }

            // Create JumpTable override
            ArrayList<Address> destList = new ArrayList<>(caseAddrs);
            // Ghidra 12.1.2 added a trailing displayFormat arg; 0 = default (no format override).
            JumpTable jt = new JumpTable(branchAddr, destList, true, 0);
            jt.writeOverride(func);

            // Rebuild function body to pick up the new cases
            CreateFunctionCmd.fixupFunctionBody(program, func, monitor);

            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }

        GhidraEngine.SwitchOverrideResult result = new GhidraEngine.SwitchOverrideResult();
        result.success = true;
        result.address = addressStr;
        result.numCases = caseAddrs.size();
        result.functionName = func.getName();
        return result;
    }

    // =====================================================================
    //  SCRIPT EXECUTION (JavaScript)
    // =====================================================================

    /**
     * Execute a Ghidra script (JavaScript via JSR 223)
     *
     * The script has access to:
     * - program: the current Program
     * - flatApi: FlatProgramAPI for common operations
     * - monitor: TaskMonitor
     * - println(msg): print to output
     * - printf(fmt, args): formatted print
     * - toAddr(str): convert string to Address
     * - getFunction(addr): get function at address
     * - decompile(func): decompile a function
     */
    public GhidraEngine.ScriptResult executeScript(String code, int timeout, boolean sandbox) throws Exception {
        Program program = ctx.getProgram();
        FlatProgramAPI flatApi = ctx.getFlatApi();
        TaskMonitor monitor = ctx.getMonitor();

        GhidraEngine.ScriptResult result = new GhidraEngine.ScriptResult();
        result.output = "";

        try {
            // Get JavaScript engine
            javax.script.ScriptEngineManager manager = new javax.script.ScriptEngineManager();
            javax.script.ScriptEngine engine = manager.getEngineByName("javascript");

            if (engine == null) {
                // Try Nashorn explicitly
                engine = manager.getEngineByName("nashorn");
            }

            if (engine == null) {
                result.success = false;
                result.error = "JavaScript engine not available. Requires Java with Nashorn or GraalJS.";
                return result;
            }

            // Create output capture
            StringBuilder outputBuilder = new StringBuilder();

            // Bind variables available to the script
            javax.script.Bindings bindings = engine.createBindings();
            bindings.put("program", program);
            bindings.put("flatApi", flatApi);
            bindings.put("monitor", monitor);
            bindings.put("currentAddress", program.getImageBase());

            // Helper functions
            String helperFunctions = """
                var output = [];
                function println(msg) { output.push(String(msg)); }
                function printf(fmt) {
                    var args = Array.prototype.slice.call(arguments, 1);
                    output.push(java.lang.String.format(fmt, args));
                }
                function toAddr(s) { return program.getAddressFactory().getAddress(s); }
                function getFunction(addr) {
                    if (typeof addr === 'string') addr = toAddr(addr);
                    return program.getFunctionManager().getFunctionAt(addr);
                }
                function getFunctionByName(name) {
                    var iter = program.getFunctionManager().getFunctions(true);
                    while (iter.hasNext()) {
                        var f = iter.next();
                        if (f.getName().equals(name)) return f;
                    }
                    return null;
                }
                function listFunctions(limit) {
                    limit = limit || 100;
                    var funcs = [];
                    var iter = program.getFunctionManager().getFunctions(true);
                    var count = 0;
                    while (iter.hasNext() && count < limit) {
                        var f = iter.next();
                        funcs.push({name: f.getName(), address: f.getEntryPoint().toString()});
                        count++;
                    }
                    return funcs;
                }
                function getDataAt(addr) {
                    if (typeof addr === 'string') addr = toAddr(addr);
                    return program.getListing().getDataAt(addr);
                }
                function getInstructionAt(addr) {
                    if (typeof addr === 'string') addr = toAddr(addr);
                    return program.getListing().getInstructionAt(addr);
                }
                function getRefsTo(addr) {
                    if (typeof addr === 'string') addr = toAddr(addr);
                    var refs = [];
                    var iter = program.getReferenceManager().getReferencesTo(addr);
                    for each (var ref in iter) {
                        refs.push({from: ref.getFromAddress().toString(), type: ref.getReferenceType().getName()});
                    }
                    return refs;
                }
                function getSymbol(addr) {
                    if (typeof addr === 'string') addr = toAddr(addr);
                    return program.getSymbolTable().getPrimarySymbol(addr);
                }
                function setComment(addr, comment, type) {
                    if (typeof addr === 'string') addr = toAddr(addr);
                    type = type || 0; // EOL_COMMENT
                    var txId = program.startTransaction("Set comment");
                    try {
                        var cu = program.getListing().getCodeUnitAt(addr);
                        if (cu) cu.setComment(type, comment);
                        program.endTransaction(txId, true);
                    } catch (e) {
                        program.endTransaction(txId, false);
                        throw e;
                    }
                }
                function rename(addr, newName) {
                    if (typeof addr === 'string') addr = toAddr(addr);
                    var txId = program.startTransaction("Rename");
                    try {
                        var func = program.getFunctionManager().getFunctionAt(addr);
                        if (func) {
                            func.setName(newName, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                        } else {
                            var sym = program.getSymbolTable().getPrimarySymbol(addr);
                            if (sym) sym.setName(newName, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                        }
                        program.endTransaction(txId, true);
                    } catch (e) {
                        program.endTransaction(txId, false);
                        throw e;
                    }
                }
                """;

            // Execute helper functions first
            engine.eval(helperFunctions, bindings);

            // Execute user code with timeout
            final javax.script.ScriptEngine finalEngine = engine;
            final javax.script.Bindings finalBindings = bindings;
            final String userCode = code + "\n; output.join('\\n');";

            java.util.concurrent.Future<Object> future = java.util.concurrent.Executors.newSingleThreadExecutor()
                .submit(() -> finalEngine.eval(userCode, finalBindings));

            try {
                Object evalResult = future.get(timeout, java.util.concurrent.TimeUnit.SECONDS);
                result.success = true;
                result.output = evalResult != null ? evalResult.toString() : "";
            } catch (java.util.concurrent.TimeoutException e) {
                future.cancel(true);
                result.success = false;
                result.error = "Script execution timed out after " + timeout + " seconds";
            }

        } catch (javax.script.ScriptException e) {
            result.success = false;
            result.error = "Script error: " + e.getMessage();
            if (e.getLineNumber() > 0) {
                result.error += " (line " + e.getLineNumber() + ")";
            }
        } catch (Exception e) {
            result.success = false;
            result.error = "Execution error: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }

        return result;
    }

    // =====================================================================
    //  JAVA SCRIPT EXECUTION (compiles a GhidraScript subclass and runs it)
    // =====================================================================

    /**
     * Executes user-supplied Java code against the loaded program.
     *
     * <p>The body is wrapped as the {@code run()} method of an anonymous
     * {@link ghidra.app.script.GhidraScript} subclass, compiled on the fly with
     * the platform {@link javax.tools.JavaCompiler}, and executed via
     * {@link ghidra.app.script.GhidraScript#execute}. We compile a real
     * {@code GhidraScript} (rather than going through Ghidra's OSGi-backed
     * {@code JavaScriptProvider}) because the OSGi {@code BundleHost} is not set
     * up under {@code HeadlessGhidraApplicationConfiguration}; a direct
     * {@code javax.tools} compile is self-contained and robust headless. The
     * compiler classpath is derived from the running JVM's {@code java.class.path}
     * (expanding any {@code lib/*} wildcard entries) so {@code ghidra.*} imports
     * resolve against the same jars the worker is already running on.
     *
     * <p>Inside the body the caller has the full {@code GhidraScript} surface:
     * {@code currentProgram} (the loaded program), {@code monitor},
     * {@code println(...)} (captured into the result output), {@code currentAddress},
     * plus every {@code GhidraScript}/{@code FlatProgramAPI} helper. Mutations must
     * be wrapped in a transaction — either via the GhidraScript helpers
     * {@code start(String)}/{@code end(boolean)} or directly with
     * {@code currentProgram.startTransaction(...)}/{@code endTransaction(...)}.
     * GhidraScript does <em>not</em> open a transaction automatically for
     * {@code run()} in this mode.
     */
    public GhidraEngine.ScriptResult executeJavaScript(String code, int timeout, boolean sandbox) throws Exception {
        final Program program = ctx.getProgram();
        final TaskMonitor monitor = ctx.getMonitor();

        GhidraEngine.ScriptResult result = new GhidraEngine.ScriptResult();
        result.output = "";

        if (program == null) {
            result.success = false;
            result.error = "No program is loaded.";
            return result;
        }

        javax.tools.JavaCompiler compiler = javax.tools.ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            result.success = false;
            result.error = "No Java compiler available (JRE without javac). "
                + "The worker must run on a JDK for language=java scripts.";
            return result;
        }

        java.io.File tmpDir = null;
        try {
            // Unique class name so repeated runs never collide in one JVM.
            String className = "GhidraMcpScript_" + Long.toHexString(System.nanoTime());
            String source =
                "import ghidra.app.script.GhidraScript;\n"
                + "import ghidra.program.model.address.*;\n"
                + "import ghidra.program.model.data.*;\n"
                + "import ghidra.program.model.listing.*;\n"
                + "import ghidra.program.model.mem.*;\n"
                + "import ghidra.program.model.pcode.*;\n"
                + "import ghidra.program.model.symbol.*;\n"
                + "import ghidra.program.model.scalar.*;\n"
                + "import ghidra.util.task.TaskMonitor;\n"
                + "import java.util.*;\n"
                + "public class " + className + " extends GhidraScript {\n"
                + "    @Override\n"
                + "    protected void run() throws Exception {\n"
                + code + "\n"
                + "    }\n"
                + "}\n";

            tmpDir = java.nio.file.Files.createTempDirectory("ghidra-mcp-java").toFile();
            java.io.File srcFile = new java.io.File(tmpDir, className + ".java");
            java.nio.file.Files.write(srcFile.toPath(), source.getBytes(java.nio.charset.StandardCharsets.UTF_8));

            // Build the compiler classpath from the running JVM so ghidra.* resolves.
            String classpath = buildCompilerClasspath();

            javax.tools.DiagnosticCollector<javax.tools.JavaFileObject> diagnostics =
                new javax.tools.DiagnosticCollector<>();
            StringWriter compilerOut = new StringWriter();
            javax.tools.StandardJavaFileManager fileManager =
                compiler.getStandardFileManager(diagnostics, null, java.nio.charset.StandardCharsets.UTF_8);

            List<String> options = new ArrayList<>(Arrays.asList(
                "-classpath", classpath,
                "-d", tmpDir.getAbsolutePath()));

            Iterable<? extends javax.tools.JavaFileObject> units =
                fileManager.getJavaFileObjects(srcFile);
            boolean compiled = compiler.getTask(
                compilerOut, fileManager, diagnostics, options, null, units).call();
            fileManager.close();

            if (!compiled) {
                StringBuilder errs = new StringBuilder("Java compilation failed:\n");
                for (javax.tools.Diagnostic<?> d : diagnostics.getDiagnostics()) {
                    // Report the line within the user body (header adds a fixed offset).
                    long line = d.getLineNumber();
                    errs.append("  ").append(d.getKind()).append(": ")
                        .append(d.getMessage(null));
                    if (line >= 0) {
                        errs.append(" (script line ~").append(Math.max(1, line - 11)).append(")");
                    }
                    errs.append("\n");
                }
                if (compilerOut.getBuffer().length() > 0) {
                    errs.append(compilerOut);
                }
                result.success = false;
                result.error = errs.toString();
                return result;
            }

            // Load and instantiate the compiled GhidraScript subclass. Parent the
            // loader on this class's loader so ghidra.* / GhidraScript resolve.
            final java.net.URLClassLoader loader = new java.net.URLClassLoader(
                new java.net.URL[]{ tmpDir.toURI().toURL() },
                getClass().getClassLoader());
            final Class<?> scriptClass = Class.forName(className, true, loader);
            final ghidra.app.script.GhidraScript script =
                (ghidra.app.script.GhidraScript) scriptClass.getDeclaredConstructor().newInstance();

            // Bind the loaded program into a GhidraState (no PluginTool headless).
            ghidra.framework.model.Project project =
                (ctx.getProject() != null) ? ctx.getProject().getProject() : null;
            final GhidraState state = new GhidraState(
                null, project, program, null, null, null);

            final StringWriter scriptOut = new StringWriter();
            final PrintWriter writer = new PrintWriter(scriptOut, true);

            Future<Void> future = java.util.concurrent.Executors.newSingleThreadExecutor().submit(() -> {
                script.execute(state, monitor, writer);
                return null;
            });

            try {
                future.get(timeout, java.util.concurrent.TimeUnit.SECONDS);
                writer.flush();
                result.success = true;
                result.output = scriptOut.toString();
            } catch (java.util.concurrent.TimeoutException e) {
                future.cancel(true);
                result.success = false;
                result.error = "Script execution timed out after " + timeout + " seconds";
                result.output = scriptOut.toString();
            } catch (java.util.concurrent.ExecutionException e) {
                writer.flush();
                Throwable cause = (e.getCause() != null) ? e.getCause() : e;
                StringWriter sw = new StringWriter();
                cause.printStackTrace(new PrintWriter(sw));
                result.success = false;
                result.error = "Script threw " + cause.getClass().getSimpleName()
                    + ": " + cause.getMessage() + "\n" + sw;
                result.output = scriptOut.toString();
            } finally {
                try { loader.close(); } catch (Exception ignore) { }
            }

        } catch (Exception e) {
            result.success = false;
            result.error = "Execution error: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            if (tmpDir != null) {
                deleteRecursive(tmpDir);
            }
        }

        return result;
    }

    /**
     * Builds a javac classpath from the running JVM's {@code java.class.path},
     * expanding any {@code .../lib/*} wildcard entries (Ghidra is launched with
     * such globs) into the concrete jars they match.
     */
    private static String buildCompilerClasspath() {
        String raw = System.getProperty("java.class.path", "");
        String sep = File.pathSeparator;
        LinkedHashSet<String> entries = new LinkedHashSet<>();
        for (String part : raw.split(Pattern.quote(sep))) {
            if (part.isEmpty()) {
                continue;
            }
            if (part.endsWith("*")) {
                java.io.File dir = new java.io.File(part.substring(0, part.length() - 1));
                java.io.File[] jars = dir.listFiles((d, n) -> n.endsWith(".jar"));
                if (jars != null) {
                    for (java.io.File jar : jars) {
                        entries.add(jar.getAbsolutePath());
                    }
                }
            } else {
                entries.add(part);
            }
        }
        return String.join(sep, entries);
    }

    private static void deleteRecursive(java.io.File f) {
        java.io.File[] kids = f.listFiles();
        if (kids != null) {
            for (java.io.File k : kids) {
                deleteRecursive(k);
            }
        }
        f.delete();
    }

    // =====================================================================
    //  PYTHON SCRIPT EXECUTION (Jython removed in 12.1 — stubbed)
    // =====================================================================

    public GhidraEngine.ScriptResult executePythonScript(String code, String filePath, int timeout, boolean sandbox)
            throws Exception {
        // Jython (ghidra.jython.*) was removed in Ghidra 12.1 in favor of PyGhidra
        // (CPython via Jep). Python execution is not wired up on this build; use the
        // Java GhidraScript path (executeScript) instead.
        GhidraEngine.ScriptResult result = new GhidraEngine.ScriptResult();
        result.success = false;
        result.output = "";
        result.error = "Python script execution is not supported on this build "
            + "(Jython was removed in Ghidra 12.1; PyGhidra port pending). "
            + "Use a Java GhidraScript via execute_script instead.";
        return result;
    }

    // =====================================================================
    //  UNDO / REDO
    // =====================================================================

    public GhidraEngine.UndoRedoResult undo() throws Exception {
        Program program = ctx.getProgram();

        if (!program.canUndo()) {
            throw new Exception("Nothing to undo");
        }

        String undoName = program.getUndoName();
        program.undo();

        GhidraEngine.UndoRedoResult result = new GhidraEngine.UndoRedoResult();
        result.actionName = undoName;
        result.canUndo = program.canUndo();
        result.canRedo = program.canRedo();
        return result;
    }

    public GhidraEngine.UndoRedoResult redo() throws Exception {
        Program program = ctx.getProgram();

        if (!program.canRedo()) {
            throw new Exception("Nothing to redo");
        }

        String redoName = program.getRedoName();
        program.redo();

        GhidraEngine.UndoRedoResult result = new GhidraEngine.UndoRedoResult();
        result.actionName = redoName;
        result.canUndo = program.canUndo();
        result.canRedo = program.canRedo();
        return result;
    }

    public GhidraEngine.UndoHistoryResult getUndoHistory() {
        Program program = ctx.getProgram();

        GhidraEngine.UndoHistoryResult result = new GhidraEngine.UndoHistoryResult();
        result.undoStack = new ArrayList<>();
        result.redoStack = new ArrayList<>();
        for (String s : program.getAllUndoNames()) {
            result.undoStack.add(s);
        }
        for (String s : program.getAllRedoNames()) {
            result.redoStack.add(s);
        }
        result.canUndo = program.canUndo();
        result.canRedo = program.canRedo();
        return result;
    }

    // =====================================================================
    //  REANALYZE
    // =====================================================================

    public GhidraEngine.ReanalyzeResult reanalyze(String addressStr) throws Exception {
        Program program = ctx.getProgram();
        TaskMonitor monitor = ctx.getMonitor();

        if (addressStr != null) {
            // Re-analyze a specific function
            Address addr = ctx.parseAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                throw new Exception("Function not found at " + addressStr);
            }

            AddressSet funcBody = new AddressSet(func.getBody());
            ghidra.app.plugin.core.analysis.AutoAnalysisManager mgr =
                ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program);
            mgr.reAnalyzeAll(funcBody);
            mgr.startAnalysis(monitor);

            GhidraEngine.ReanalyzeResult result = new GhidraEngine.ReanalyzeResult();
            result.success = true;
            result.scope = "function";
            return result;
        } else {
            // Re-analyze entire program
            ghidra.app.plugin.core.analysis.AutoAnalysisManager mgr =
                ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program);
            mgr.reAnalyzeAll(null);
            mgr.startAnalysis(monitor);

            GhidraEngine.ReanalyzeResult result = new GhidraEngine.ReanalyzeResult();
            result.success = true;
            result.scope = "program";
            return result;
        }
    }

    // =====================================================================
    //  EXPORT ALL C
    // =====================================================================

    /**
     * Export all pseudo-C code including type definitions and all functions
     * Returns a structured result with headers and implementation code
     */
    public GhidraEngine.ExportAllCResult exportAllC(int timeout, boolean includeTypes, boolean includeHeaders) {
        Program program = ctx.getProgram();
        DecompInterface decompiler = ctx.getDecompiler();
        TaskMonitor monitor = ctx.getMonitor();

        GhidraEngine.ExportAllCResult result = new GhidraEngine.ExportAllCResult();
        result.cacheVersion = ctx.getCacheVersion();
        result.functionCount = 0;
        result.typeCount = 0;

        StringBuilder typeDefs = new StringBuilder();
        StringBuilder forwardDecls = new StringBuilder();
        StringBuilder functionCode = new StringBuilder();
        List<GhidraEngine.ExportedFunction> functions = new ArrayList<>();

        // Export type definitions
        if (includeTypes) {
            DataTypeManager dtm = program.getDataTypeManager();

            // Collect forward declarations and type definitions
            Set<String> declaredTypes = new HashSet<>();

            Iterator<DataType> iter = dtm.getAllDataTypes();
            while (iter.hasNext()) {
                DataType dt = iter.next();
                String typeName = dt.getName();

                // Skip built-in types
                if (dt.getCategoryPath().getPath().startsWith("/")) {
                    String cat = dt.getCategoryPath().getPath();
                    if (cat.equals("/") || cat.startsWith("/undefined") ||
                        dt instanceof BuiltInDataType) {
                        continue;
                    }
                }

                result.typeCount++;

                if (dt instanceof Structure) {
                    Structure struct = (Structure) dt;
                    // Forward declaration
                    if (!declaredTypes.contains(typeName)) {
                        forwardDecls.append("struct ").append(typeName).append(";\n");
                        declaredTypes.add(typeName);
                    }
                    // Full definition
                    typeDefs.append(structToC(struct)).append("\n\n");
                } else if (dt instanceof ghidra.program.model.data.Enum) {
                    ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
                    typeDefs.append(enumToC(enumType)).append("\n\n");
                } else if (dt instanceof TypeDef) {
                    TypeDef typedef = (TypeDef) dt;
                    typeDefs.append("typedef ").append(typedef.getBaseDataType().getName())
                           .append(" ").append(typedef.getName()).append(";\n");
                } else if (dt instanceof Union) {
                    Union union = (Union) dt;
                    typeDefs.append(unionToC(union)).append("\n\n");
                } else if (dt instanceof FunctionDefinition) {
                    FunctionDefinition funcDef = (FunctionDefinition) dt;
                    typeDefs.append(functionDefToC(funcDef)).append("\n");
                }
            }
        }

        // Count total functions first for progress reporting
        int totalFunctions = 0;
        Iterator<Function> countIter = program.getFunctionManager().getFunctions(true);
        while (countIter.hasNext()) {
            countIter.next();
            totalFunctions++;
        }

        ctx.getLog().info("Exporting " + totalFunctions + " functions...");

        // Export all functions (parallel via pool when available)
        com.ghidramcp.DecompilerPool pool = ctx.getDecompilerPool();
        List<Function> allFunctions = new ArrayList<>();
        Iterator<Function> funcIter = program.getFunctionManager().getFunctions(true);
        while (funcIter.hasNext()) {
            allFunctions.add(funcIter.next());
        }

        int processedCount = 0;
        int lastReportedPct = 0;

        if (pool != null) {
            // Parallel: submit in chunks of poolSize*4
            int chunkSize = pool.getPoolSize() * 4;
            for (int start = 0; start < allFunctions.size(); start += chunkSize) {
                int end = Math.min(start + chunkSize, allFunctions.size());
                List<Function> chunk = allFunctions.subList(start, end);
                List<Future<DecompileResults>> futures = new ArrayList<>(chunk.size());

                for (Function func : chunk) {
                    futures.add(pool.submit(func, timeout));
                }

                for (int i = 0; i < chunk.size(); i++) {
                    Function func = chunk.get(i);
                    GhidraEngine.ExportedFunction expFunc = new GhidraEngine.ExportedFunction();
                    expFunc.name = func.getName();
                    expFunc.address = func.getEntryPoint().toString();
                    expFunc.signature = func.getSignature().getPrototypeString();
                    Namespace ns = func.getParentNamespace();
                    if (ns != null && !ns.isGlobal()) {
                        expFunc.namespace = ns.getName(true);
                    }

                    try {
                        DecompileResults results = futures.get(i).get();
                        if (results.decompileCompleted()) {
                            expFunc.code = results.getDecompiledFunction().getC();
                            expFunc.success = true;
                        } else {
                            expFunc.code = "// Decompilation failed: " + results.getErrorMessage();
                            expFunc.success = false;
                            expFunc.error = results.getErrorMessage();
                        }
                    } catch (Exception e) {
                        Throwable cause = e.getCause() != null ? e.getCause() : e;
                        expFunc.code = "// Decompilation error: " + cause.getMessage();
                        expFunc.success = false;
                        expFunc.error = cause.getMessage();
                    }

                    functions.add(expFunc);
                    result.functionCount++;
                    processedCount++;
                }

                int pct = (processedCount * 100) / totalFunctions;
                if (pct >= lastReportedPct + 10 || processedCount == totalFunctions) {
                    ctx.getLog().info("[export_all_c] Progress: " + processedCount + "/" + totalFunctions + " (" + pct + "%)");
                    lastReportedPct = pct;
                }
            }
        } else {
            // Sequential fallback
            for (Function func : allFunctions) {
                GhidraEngine.ExportedFunction expFunc = new GhidraEngine.ExportedFunction();
                expFunc.name = func.getName();
                expFunc.address = func.getEntryPoint().toString();
                expFunc.signature = func.getSignature().getPrototypeString();
                Namespace ns = func.getParentNamespace();
                if (ns != null && !ns.isGlobal()) {
                    expFunc.namespace = ns.getName(true);
                }

                try {
                    DecompileResults results = decompiler.decompileFunction(func, timeout, monitor);
                    if (results.decompileCompleted()) {
                        expFunc.code = results.getDecompiledFunction().getC();
                        expFunc.success = true;
                    } else {
                        expFunc.code = "// Decompilation failed: " + results.getErrorMessage();
                        expFunc.success = false;
                        expFunc.error = results.getErrorMessage();
                    }
                } catch (Exception e) {
                    expFunc.code = "// Decompilation error: " + e.getMessage();
                    expFunc.success = false;
                    expFunc.error = e.getMessage();
                }

                functions.add(expFunc);
                result.functionCount++;
                processedCount++;

                int pct = (processedCount * 100) / totalFunctions;
                if (pct >= lastReportedPct + 10 || processedCount == totalFunctions) {
                    ctx.getLog().info("[export_all_c] Progress: " + processedCount + "/" + totalFunctions + " (" + pct + "%)");
                    lastReportedPct = pct;
                }
            }
        }

        // Build the complete output
        if (includeHeaders) {
            result.headerCode = forwardDecls.toString() + "\n" + typeDefs.toString();
        }

        // Combine all function code
        for (GhidraEngine.ExportedFunction ef : functions) {
            functionCode.append("// ").append(ef.address).append(": ").append(ef.name).append("\n");
            functionCode.append(ef.code).append("\n\n");
        }

        result.implementationCode = functionCode.toString();
        result.functions = functions;

        return result;
    }

    // =====================================================================
    //  EXPORT ALL C — TYPE HELPERS
    // =====================================================================

    private String structToC(Structure struct) {
        StringBuilder sb = new StringBuilder();
        sb.append("struct ").append(struct.getName()).append(" {\n");

        for (DataTypeComponent comp : struct.getComponents()) {
            String fieldType = comp.getDataType().getName();
            String fieldName = comp.getFieldName();
            if (fieldName == null || fieldName.isEmpty()) {
                fieldName = "field_0x" + Integer.toHexString(comp.getOffset());
            }
            sb.append("    ").append(fieldType).append(" ").append(fieldName).append(";");
            if (comp.getComment() != null && !comp.getComment().isEmpty()) {
                sb.append(" // ").append(comp.getComment());
            }
            sb.append("\n");
        }

        sb.append("};");
        return sb.toString();
    }

    private String enumToC(ghidra.program.model.data.Enum enumType) {
        StringBuilder sb = new StringBuilder();
        sb.append("enum ").append(enumType.getName()).append(" {\n");

        String[] names = enumType.getNames();
        for (int i = 0; i < names.length; i++) {
            sb.append("    ").append(names[i]).append(" = ").append(enumType.getValue(names[i]));
            if (i < names.length - 1) sb.append(",");
            sb.append("\n");
        }

        sb.append("};");
        return sb.toString();
    }

    private String unionToC(Union union) {
        StringBuilder sb = new StringBuilder();
        sb.append("union ").append(union.getName()).append(" {\n");

        for (DataTypeComponent comp : union.getComponents()) {
            String fieldType = comp.getDataType().getName();
            String fieldName = comp.getFieldName();
            if (fieldName == null || fieldName.isEmpty()) {
                fieldName = "field_" + comp.getOrdinal();
            }
            sb.append("    ").append(fieldType).append(" ").append(fieldName).append(";\n");
        }

        sb.append("};");
        return sb.toString();
    }

    private String functionDefToC(FunctionDefinition funcDef) {
        return "typedef " + funcDef.getPrototypeString() + ";";
    }

    // =====================================================================
    //  FUNCTION VARIABLE NAME / TYPE
    // =====================================================================

    /**
     * Rename a function variable.
     * Accepts both Ghidra API names (local_8, param_1) and decompiler names (iVar1, puVar2).
     */
    public void setFunctionVariableName(String functionAddressStr, String oldName, String newName, String description) throws Exception {
        setFunctionVariableName(functionAddressStr, oldName, newName, description, false);
    }

    public void setFunctionVariableName(String functionAddressStr, String oldName, String newName, String description, boolean force) throws Exception {
        Program program = ctx.getProgram();
        DecompInterface decompiler = ctx.getDecompiler();
        TaskMonitor monitor = ctx.getMonitor();

        Address address = ctx.parseAddress(functionAddressStr);
        Function func = program.getFunctionManager().getFunctionAt(address);

        if (func == null) {
            throw new Exception("Function not found at: " + functionAddressStr);
        }

        String entryAddr = func.getEntryPoint().toString();
        ctx.assertReadBeforeWrite(entryAddr, func.getName(), force);

        // Fast path: try direct match against API names (no decompile needed)
        boolean foundDirect = false;
        for (Parameter param : func.getParameters()) {
            if (param.getName().equals(oldName)) { foundDirect = true; break; }
        }
        if (!foundDirect) {
            for (Variable var : func.getLocalVariables()) {
                if (var.getName().equals(oldName)) { foundDirect = true; break; }
            }
        }

        if (foundDirect) {
            int txId = program.startTransaction("Rename variable");
            try {
                for (Parameter param : func.getParameters()) {
                    if (param.getName().equals(oldName)) {
                        param.setName(newName, SourceType.USER_DEFINED);
                        ctx.updateFunctionPlateComment(func, description);
                        program.endTransaction(txId, true);
                        ctx.updateFunctionModCount(entryAddr);
                        return;
                    }
                }
                for (Variable var : func.getLocalVariables()) {
                    if (var.getName().equals(oldName)) {
                        var.setName(newName, SourceType.USER_DEFINED);
                        ctx.updateFunctionPlateComment(func, description);
                        program.endTransaction(txId, true);
                        ctx.updateFunctionModCount(entryAddr);
                        return;
                    }
                }
                program.endTransaction(txId, false);
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
        }

        // Slow path: decompile OUTSIDE transaction, then apply rename inside transaction
        HighSymbol highSym = findHighSymbolByName(func, oldName);
        if (highSym == null) {
            throw new Exception("Variable not found: " + oldName +
                ". Available variables: " + buildAvailableVarList(func));
        }

        int txId = program.startTransaction("Rename variable (decompiler)");
        try {
            // Pass explicit name, null dataType (preserves existing type for params;
            // for locals, Ghidra falls back to preexisting or Undefined)
            HighFunctionDBUtil.updateDBVariable(highSym, newName, null, SourceType.USER_DEFINED);
            ctx.updateFunctionPlateComment(func, description);
            program.endTransaction(txId, true);
            ctx.updateFunctionModCount(entryAddr);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Change a function variable's type.
     * Accepts both Ghidra API names (local_8, param_1) and decompiler names (iVar1, puVar2).
     */
    public void setFunctionVariableType(String functionAddressStr, String variableName, String dataTypeName, String description) throws Exception {
        setFunctionVariableType(functionAddressStr, variableName, dataTypeName, description, true, false);
    }

    public void setFunctionVariableType(String functionAddressStr, String variableName, String dataTypeName, String description, boolean forceRemoveConflicts) throws Exception {
        setFunctionVariableType(functionAddressStr, variableName, dataTypeName, description, forceRemoveConflicts, false);
    }

    public void setFunctionVariableType(String functionAddressStr, String variableName, String dataTypeName, String description, boolean forceRemoveConflicts, boolean forceGuard) throws Exception {
        Program program = ctx.getProgram();
        DecompInterface decompiler = ctx.getDecompiler();
        TaskMonitor monitor = ctx.getMonitor();

        Address address = ctx.parseAddress(functionAddressStr);
        Function func = program.getFunctionManager().getFunctionAt(address);

        if (func == null) {
            throw new Exception("Function not found at: " + functionAddressStr);
        }

        String entryAddr = func.getEntryPoint().toString();
        ctx.assertReadBeforeWrite(entryAddr, func.getName(), forceGuard);

        DataType newType = ctx.resolveDataType(dataTypeName);

        // Fast path: try direct match against API names (no decompile needed)
        Variable targetVar = null;
        for (Parameter param : func.getParameters()) {
            if (param.getName().equals(variableName)) { targetVar = param; break; }
        }
        if (targetVar == null) {
            for (Variable var : func.getLocalVariables()) {
                if (var.getName().equals(variableName)) { targetVar = var; break; }
            }
        }

        if (targetVar != null) {
            int txId = program.startTransaction("Set variable type");
            try {
                if (forceRemoveConflicts && targetVar.isStackVariable()) {
                    // Remove any other stack locals that overlap the target's new range
                    int targetOffset = targetVar.getStackOffset();
                    int newSize = newType.getLength();
                    List<Variable> toRemove = new ArrayList<>();
                    for (Variable var : func.getLocalVariables()) {
                        if (var == targetVar || !var.isStackVariable()) continue;
                        int vOff = var.getStackOffset();
                        int vSize = var.getLength();
                        // Check overlap: [targetOffset, targetOffset+newSize) vs [vOff, vOff+vSize)
                        if (vOff >= targetOffset && vOff < targetOffset + newSize) {
                            toRemove.add(var);
                        } else if (targetOffset >= vOff && targetOffset < vOff + vSize) {
                            toRemove.add(var);
                        }
                    }
                    for (Variable var : toRemove) {
                        func.removeVariable(var);
                    }
                }
                targetVar.setDataType(newType, SourceType.USER_DEFINED);
                ctx.updateFunctionPlateComment(func, description);
                program.endTransaction(txId, true);
                ctx.updateFunctionModCount(entryAddr);
                return;
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
        }

        // Slow path: decompile OUTSIDE transaction, then apply type inside transaction
        HighSymbol highSym = findHighSymbolByName(func, variableName);
        if (highSym == null) {
            throw new Exception("Variable not found: " + variableName +
                ". Available variables: " + buildAvailableVarList(func));
        }

        int txId = program.startTransaction("Set variable type (decompiler)");
        try {
            // For params: null dataType is skipped (safe). We pass explicit type.
            // For locals: null name triggers highSymbol.getName() fallback which
            //   actively writes the decompiler name — so we pass the current name explicitly
            //   to avoid side-effecting a rename when we only want to retype.
            String currentName = highSym.getName();
            HighFunctionDBUtil.updateDBVariable(highSym, currentName, newType, SourceType.USER_DEFINED);
            ctx.updateFunctionPlateComment(func, description);
            program.endTransaction(txId, true);
            ctx.updateFunctionModCount(entryAddr);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Decompile a function and find a HighSymbol by its decompiler-assigned name.
     * This bridges the gap between decompiler names (iVar1, puVar2) and
     * Ghidra API names (local_8, local_c).
     *
     * Lookup order:
     *  1. Exact name match
     *  2. Case-insensitive name match
     *  3. Match against the symbol's storage string (e.g. "Stack[-0x8:4]")
     *
     * Returns null on miss; callers should call listAvailableVariableNames() to build
     * a helpful error message.
     */
    private HighSymbol findHighSymbolByName(Function func, String name) {
        return findHighSymbolByName(func, name, null);
    }

    /**
     * Variant that also returns the full symbol list via an out-list so callers can
     * build a "variable not found, available: ..." message without decompiling twice.
     */
    private HighSymbol findHighSymbolByName(Function func, String name, List<String> availableNamesOut) {
        try {
            DecompileResults results = ctx.getDecompiler().decompileFunction(func, 30, ctx.getMonitor());
            if (results == null || !results.decompileCompleted()) return null;

            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null) return null;

            LocalSymbolMap symbolMap = highFunc.getLocalSymbolMap();

            HighSymbol exactMatch = null;
            HighSymbol caseInsensitiveMatch = null;
            HighSymbol storageMatch = null;

            List<HighSymbol> allSyms = new ArrayList<>();
            Iterator<HighSymbol> symIter = symbolMap.getSymbols();
            while (symIter.hasNext()) {
                HighSymbol sym = symIter.next();
                allSyms.add(sym);

                if (exactMatch == null && sym.getName().equals(name)) {
                    exactMatch = sym;
                }
                if (caseInsensitiveMatch == null && sym.getName().equalsIgnoreCase(name)) {
                    caseInsensitiveMatch = sym;
                }
                if (storageMatch == null && sym.getStorage() != null
                        && sym.getStorage().toString().equals(name)) {
                    storageMatch = sym;
                }
            }

            if (availableNamesOut != null) {
                for (HighSymbol sym : allSyms) {
                    availableNamesOut.add(sym.getName());
                }
            }

            if (exactMatch != null) return exactMatch;
            if (caseInsensitiveMatch != null) return caseInsensitiveMatch;
            return storageMatch;
        } catch (Exception e) {
            // Decompilation failed — fall through
        }
        return null;
    }

    /**
     * Build a string listing available variable names for a function: params, locals, and
     * decompiler HighSymbol names.  Used in "variable not found" error messages.
     */
    private String buildAvailableVarList(Function func) {
        List<String> names = new ArrayList<>();
        for (Parameter p : func.getParameters()) names.add(p.getName());
        for (Variable v : func.getLocalVariables()) names.add(v.getName());
        List<String> highNames = new ArrayList<>();
        findHighSymbolByName(func, "__probe__", highNames); // side-effect: fills highNames
        for (String hn : highNames) {
            if (!names.contains(hn)) names.add(hn);
        }
        return String.join(", ", names);
    }

    // =====================================================================
    //  PRIVATE HELPER: getFunction (inlined from FunctionOps)
    // =====================================================================

    /**
     * Get a function by address or name. Simple lookup used by getPcode, getStackFrame, etc.
     */
    private Function getFunction(String address, String name) {
        Program program = ctx.getProgram();
        if (address != null) {
            Address addr = ctx.parseAddress(address);
            return program.getFunctionManager().getFunctionAt(addr);
        } else if (name != null) {
            Iterator<Function> iter = program.getFunctionManager().getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                if (func.getName().equals(name)) {
                    return func;
                }
            }
        }
        return null;
    }
}
