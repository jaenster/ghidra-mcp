package com.ghidramcp.operations;

import com.ghidramcp.GhidraContext;
import com.ghidramcp.GhidraEngine;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Symbol, namespace, comment, bookmark, label, equate, function attribute, and tag operations.
 * Covers all symbol-table mutations and queries that don't involve data types or decompilation.
 */
public class SymbolOps {
    private final GhidraContext ctx;

    public SymbolOps(GhidraContext ctx) {
        this.ctx = ctx;
    }

    // ==================== SYMBOL RENAME ====================

    /**
     * Rename a symbol (function, label, or data).
     */
    public void renameSymbol(String addressStr, String newName, String type, String description) throws Exception {
        Program program = ctx.getProgram();
        Address address = ctx.parseAddress(addressStr);

        int txId = program.startTransaction("Rename symbol");
        try {
            if ("function".equals(type)) {
                Function func = program.getFunctionManager().getFunctionAt(address);
                if (func != null) {
                    func.setName(newName, SourceType.USER_DEFINED);
                    ctx.updateFunctionPlateComment(func, description);
                }
            } else {
                Symbol sym = program.getSymbolTable().getPrimarySymbol(address);
                if (sym != null) {
                    sym.setName(newName, SourceType.USER_DEFINED);
                }
            }
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Batch rename symbols.
     */
    public GhidraEngine.BatchRenameResult batchRename(List<GhidraEngine.RenameMapping> mappings, boolean dryRun, String description) throws Exception {
        Program program = ctx.getProgram();
        GhidraEngine.BatchRenameResult result = new GhidraEngine.BatchRenameResult();
        result.succeeded = new ArrayList<>();
        result.failed = new ArrayList<>();

        int txId = dryRun ? -1 : program.startTransaction("Batch rename");
        try {
            for (GhidraEngine.RenameMapping mapping : mappings) {
                try {
                    if (!dryRun) {
                        Address address = ctx.parseAddress(mapping.address);
                        Symbol sym = program.getSymbolTable().getPrimarySymbol(address);
                        if (sym != null) {
                            sym.setName(mapping.newName, SourceType.USER_DEFINED);
                            // Update PLATE for function symbols
                            Function func = program.getFunctionManager().getFunctionAt(address);
                            if (func != null) {
                                ctx.updateFunctionPlateComment(func, description);
                            }
                        } else {
                            Function func = program.getFunctionManager().getFunctionAt(address);
                            if (func != null) {
                                func.setName(mapping.newName, SourceType.USER_DEFINED);
                                ctx.updateFunctionPlateComment(func, description);
                            }
                        }
                    }
                    result.succeeded.add(mapping.address + " -> " + mapping.newName);
                } catch (Exception e) {
                    result.failed.add(mapping.address + ": " + e.getMessage());
                }
            }

            if (!dryRun) {
                program.endTransaction(txId, true);
            }
        } catch (Exception e) {
            if (!dryRun && txId >= 0) {
                program.endTransaction(txId, false);
            }
            throw e;
        }

        result.dryRun = dryRun;
        return result;
    }

    // ==================== SYMBOL LISTING ====================

    /**
     * List all symbols with filtering.
     */
    public List<GhidraEngine.SymbolInfo> listSymbols(int offset, int limit, String filter, String regex, String type) {
        Program program = ctx.getProgram();
        List<GhidraEngine.SymbolInfo> symbols = new ArrayList<>();
        SymbolTable symTable = program.getSymbolTable();
        Object[] filterArgs = GhidraContext.prepareFilter(filter, regex);
        String filterLower = (String) filterArgs[0];
        Pattern compiled = (Pattern) filterArgs[1];

        int count = 0;
        int skipped = 0;

        for (Symbol sym : symTable.getAllSymbols(true)) {
            // Filter by type
            if (type != null && !sym.getSymbolType().toString().equalsIgnoreCase(type)) {
                continue;
            }

            if (!GhidraContext.passesFilter(sym.getName(), filterLower, compiled)) {
                continue;
            }

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (count >= limit) break;

            GhidraEngine.SymbolInfo info = new GhidraEngine.SymbolInfo();
            info.name = sym.getName();
            info.address = sym.getAddress().toString();
            info.type = sym.getSymbolType().toString();
            info.isPrimary = sym.isPrimary();
            info.isExternal = sym.isExternal();

            Namespace ns = sym.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                info.namespace = ns.getName(true);  // Full path
            }

            // Parse structured tags (function tags or bookmarks)
            Address addr = sym.getAddress();
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func != null) {
                List<JsonObject> parsedTags = ctx.parseStructuredTags(func);
                if (!parsedTags.isEmpty()) {
                    info.tags = parsedTags;
                }
            } else {
                List<JsonObject> parsedTags = ctx.parseStructuredTagsFromBookmarks(addr);
                if (!parsedTags.isEmpty()) {
                    info.tags = parsedTags;
                }
            }

            symbols.add(info);
            count++;
        }

        return symbols;
    }

    // ==================== IMPORTS / EXPORTS ====================

    /**
     * List imported symbols.
     */
    public List<GhidraEngine.ImportInfo> listImports(int offset, int limit, String filter, String regex) {
        Program program = ctx.getProgram();
        List<GhidraEngine.ImportInfo> imports = new ArrayList<>();
        SymbolTable symTable = program.getSymbolTable();
        Object[] filterArgs = GhidraContext.prepareFilter(filter, regex);
        String filterLower = (String) filterArgs[0];
        Pattern compiled = (Pattern) filterArgs[1];

        int count = 0;
        int skipped = 0;

        for (Symbol sym : symTable.getExternalSymbols()) {
            if (!GhidraContext.passesFilter(sym.getName(), filterLower, compiled)) continue;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (count >= limit) break;

            GhidraEngine.ImportInfo info = new GhidraEngine.ImportInfo();
            info.name = sym.getName();
            info.address = sym.getAddress().toString();

            ExternalLocation extLoc = program.getExternalManager()
                .getExternalLocation(sym);
            if (extLoc != null) {
                info.library = extLoc.getLibraryName();
            }

            imports.add(info);
            count++;
        }

        return imports;
    }

    /**
     * List exported symbols.
     */
    public List<GhidraEngine.ExportInfo> listExports(int offset, int limit, String filter, String regex) {
        Program program = ctx.getProgram();
        List<GhidraEngine.ExportInfo> exports = new ArrayList<>();
        SymbolTable symTable = program.getSymbolTable();
        Object[] filterArgs = GhidraContext.prepareFilter(filter, regex);
        String filterLower = (String) filterArgs[0];
        Pattern compiled = (Pattern) filterArgs[1];

        int count = 0;
        int skipped = 0;

        for (Symbol sym : symTable.getAllSymbols(true)) {
            if (!sym.isExternalEntryPoint()) continue;
            if (!GhidraContext.passesFilter(sym.getName(), filterLower, compiled)) continue;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (count >= limit) break;

            GhidraEngine.ExportInfo info = new GhidraEngine.ExportInfo();
            info.name = sym.getName();
            info.address = sym.getAddress().toString();
            exports.add(info);
            count++;
        }

        return exports;
    }

    // ==================== NAMESPACES ====================

    /**
     * List namespaces in the program.
     * Pre-computes function counts in one pass (O(functions) instead of O(namespaces * functions)).
     * Matches full namespace path (e.g., filter "D2Client::UI" works).
     */
    public List<GhidraEngine.NamespaceInfo> listNamespaces(int offset, int limit, String filter, String regex) {
        Program program = ctx.getProgram();
        List<GhidraEngine.NamespaceInfo> namespaces = new ArrayList<>();
        Object[] filterArgs = GhidraContext.prepareFilter(filter, regex);
        String filterLower = (String) filterArgs[0];
        Pattern compiled = (Pattern) filterArgs[1];

        // Pre-compute function counts per namespace in ONE pass
        Map<Namespace, Integer> nsFuncCounts = new HashMap<>();
        FunctionManager fm = program.getFunctionManager();
        for (Function func : fm.getFunctions(true)) {
            Namespace ns = func.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                nsFuncCounts.merge(ns, 1, Integer::sum);
            }
        }

        // Collect all namespaces via tree walk
        Set<String> seen = new HashSet<>();
        int[] counter = {0}; // mutable counter shared across recursion: [0]=total matched
        collectNamespacesRecursive(program.getGlobalNamespace(), namespaces, seen,
            filterLower, compiled, offset, limit, nsFuncCounts, counter);

        return namespaces;
    }

    private void collectNamespacesRecursive(Namespace parent, List<GhidraEngine.NamespaceInfo> results,
                                             Set<String> seen, String filterLower, Pattern compiled,
                                             int offset, int limit,
                                             Map<Namespace, Integer> nsFuncCounts,
                                             int[] counter) {
        Program program = ctx.getProgram();
        SymbolTable symTable = program.getSymbolTable();
        for (Symbol sym : symTable.getSymbols(parent)) {
            if (sym.getSymbolType() != SymbolType.NAMESPACE &&
                sym.getSymbolType() != SymbolType.CLASS) {
                continue;
            }

            Namespace ns = (Namespace) sym.getObject();
            if (ns == null || ns.equals(parent)) continue;

            String fullPath = ns.getName(true);
            if (!seen.add(fullPath)) continue; // deduplicate

            // Filter matches full path
            if (GhidraContext.passesFilter(fullPath, filterLower, compiled)) {
                int idx = counter[0]++;
                if (idx >= offset && results.size() < limit) {
                    GhidraEngine.NamespaceInfo info = new GhidraEngine.NamespaceInfo();
                    info.name = ns.getName();
                    info.fullPath = fullPath;
                    info.isClass = sym.getSymbolType() == SymbolType.CLASS;
                    info.address = sym.getAddress() != null ? sym.getAddress().toString() : null;
                    info.functionCount = nsFuncCounts.getOrDefault(ns, 0);

                    Namespace p = ns.getParentNamespace();
                    if (p != null && !p.isGlobal()) {
                        info.parentNamespace = p.getName();
                    }
                    results.add(info);
                }
            }

            // Always recurse to find matching children
            collectNamespacesRecursive(ns, results, seen, filterLower, compiled, offset, limit, nsFuncCounts, counter);
        }
    }

    /**
     * Create a new namespace or class.
     */
    public GhidraEngine.NamespaceResult createNamespace(String name, String parent, boolean isClass) throws Exception {
        Program program = ctx.getProgram();
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace parentNs;

        if (parent != null && !parent.isEmpty() && !parent.equals("Global")) {
            if (parent.contains("::")) {
                String[] parts = parent.split("::");
                Namespace current = program.getGlobalNamespace();
                for (String part : parts) {
                    Namespace next = symbolTable.getNamespace(part, current);
                    if (next == null) {
                        throw new Exception("Parent namespace not found: " + parent + " (failed at: " + part + ")");
                    }
                    current = next;
                }
                parentNs = current;
            } else {
                parentNs = symbolTable.getNamespace(parent, null);
                if (parentNs == null) {
                    throw new Exception("Parent namespace not found: " + parent);
                }
            }
        } else {
            parentNs = program.getGlobalNamespace();
        }

        int txId = program.startTransaction("Create namespace");
        try {
            Namespace ns;
            if (isClass) {
                ns = symbolTable.createClass(parentNs, name, SourceType.USER_DEFINED);
            } else {
                ns = symbolTable.createNameSpace(parentNs, name, SourceType.USER_DEFINED);
            }
            program.endTransaction(txId, true);

            GhidraEngine.NamespaceResult result = new GhidraEngine.NamespaceResult();
            result.name = ns.getName();
            result.parentNamespace = ns.getParentNamespace().getName();
            result.isClass = ns instanceof ghidra.program.model.listing.GhidraClass;
            return result;
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Move a symbol (function, label, or data) to a different namespace.
     */
    public GhidraEngine.MoveSymbolResult moveSymbolToNamespace(String addressStr, String namespaceName, String type) throws Exception {
        Program program = ctx.getProgram();
        Address address = ctx.parseAddress(addressStr);
        SymbolTable symbolTable = program.getSymbolTable();

        // Handle namespace paths like "D2Game::Quests" — auto-creates missing segments
        Namespace targetNs = null;
        if (namespaceName.contains("::")) {
            String[] parts = namespaceName.split("::");
            Namespace current = program.getGlobalNamespace();
            int autoCreateTxId = program.startTransaction("Create namespaces for move");
            try {
                for (String part : parts) {
                    Namespace next = symbolTable.getNamespace(part, current);
                    if (next == null) {
                        next = symbolTable.createNameSpace(current, part, SourceType.USER_DEFINED);
                    }
                    current = next;
                }
                program.endTransaction(autoCreateTxId, true);
            } catch (Exception e) {
                program.endTransaction(autoCreateTxId, false);
                throw new Exception("Namespace not found/creatable: " + namespaceName, e);
            }
            targetNs = current;
        } else {
            targetNs = symbolTable.getNamespace(namespaceName, null);
        }

        if (targetNs == null) {
            throw new Exception("Namespace not found: " + namespaceName);
        }

        Symbol sym;
        if ("function".equals(type)) {
            Function func = program.getFunctionManager().getFunctionAt(address);
            if (func == null) {
                throw new Exception("Function not found at " + addressStr);
            }
            sym = func.getSymbol();
        } else {
            sym = symbolTable.getPrimarySymbol(address);
            if (sym == null) {
                throw new Exception("Symbol not found at " + addressStr);
            }
        }

        String oldNs = sym.getParentNamespace().getName();

        int txId = program.startTransaction("Move symbol to namespace");
        try {
            sym.setNamespace(targetNs);
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }

        GhidraEngine.MoveSymbolResult result = new GhidraEngine.MoveSymbolResult();
        result.name = sym.getName();
        result.oldNamespace = oldNs;
        result.newNamespace = namespaceName;
        return result;
    }

    /**
     * Rename an existing namespace.
     */
    public void renameNamespace(String oldName, String newName) throws Exception {
        Program program = ctx.getProgram();
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace ns = symbolTable.getNamespace(oldName, null);
        if (ns == null) {
            throw new Exception("Namespace not found: " + oldName);
        }

        int txId = program.startTransaction("Rename namespace");
        try {
            ns.getSymbol().setName(newName, SourceType.USER_DEFINED);
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Get class/namespace information including methods and parent.
     */
    public GhidraEngine.ClassInfo getClassInfo(String name) throws Exception {
        Program program = ctx.getProgram();
        SymbolTable symTable = program.getSymbolTable();
        Namespace ns = null;

        // Find the namespace/class
        for (Symbol sym : symTable.getAllSymbols(true)) {
            if (sym.getSymbolType() == SymbolType.CLASS || sym.getSymbolType() == SymbolType.NAMESPACE) {
                if (sym.getName().equals(name)) {
                    ns = (Namespace) sym.getObject();
                    break;
                }
            }
        }

        if (ns == null) {
            throw new Exception("Class/namespace not found: " + name);
        }

        GhidraEngine.ClassInfo info = new GhidraEngine.ClassInfo();
        info.name = ns.getName();
        info.fullPath = ns.getName(true);

        // Check if this namespace is a class by looking at its symbol type
        Symbol nsSym = ns.getSymbol();
        info.isClass = nsSym != null && nsSym.getSymbolType() == SymbolType.CLASS;

        // Get methods/functions
        info.methods = new ArrayList<>();
        FunctionManager funcMgr = program.getFunctionManager();
        for (Function func : funcMgr.getFunctions(true)) {
            if (func.getParentNamespace().equals(ns)) {
                GhidraEngine.FunctionInfo fInfo = buildFunctionInfoForClass(func);
                info.methods.add(fInfo);
            }
        }

        // Get parent namespace
        Namespace parent = ns.getParentNamespace();
        if (parent != null && !parent.isGlobal()) {
            info.parentClass = parent.getName();
        }

        return info;
    }

    /**
     * Build a FunctionInfo for class method listing.
     * Duplicates the essential logic from GhidraEngine.getFunctionInfo to avoid cross-ops dependency.
     */
    private GhidraEngine.FunctionInfo buildFunctionInfoForClass(Function func) {
        Program program = ctx.getProgram();
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

        Namespace ns = func.getParentNamespace();
        if (ns != null && !ns.isGlobal()) {
            info.namespace = ns.getName(true);
        }

        // Parameters
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

        // Local variables
        info.localVariables = new ArrayList<>();
        for (Variable var : func.getAllVariables()) {
            if (var instanceof Parameter) continue;
            GhidraEngine.VariableInfo vinfo = new GhidraEngine.VariableInfo();
            vinfo.name = var.getName();
            vinfo.dataType = var.getDataType().getName();
            vinfo.size = var.getLength();
            vinfo.storage = var.getVariableStorage().toString();
            vinfo.stackOffset = var.isStackVariable() ? var.getStackOffset() : null;
            info.localVariables.add(vinfo);
        }

        // Tags
        List<JsonObject> parsedTags = ctx.parseStructuredTags(func);
        if (!parsedTags.isEmpty()) {
            info.tags = parsedTags;
        }

        return info;
    }

    // ==================== COMMENTS ====================

    /**
     * Set a comment at an address.
     */
    public void setComment(String addressStr, String comment, String type) throws Exception {
        Program program = ctx.getProgram();
        Address address = ctx.parseAddress(addressStr);

        int commentType;
        switch (type) {
            case "EOL": commentType = CodeUnit.EOL_COMMENT; break;
            case "PRE": commentType = CodeUnit.PRE_COMMENT; break;
            case "POST": commentType = CodeUnit.POST_COMMENT; break;
            case "PLATE": commentType = CodeUnit.PLATE_COMMENT; break;
            case "REPEATABLE": commentType = CodeUnit.REPEATABLE_COMMENT; break;
            default: commentType = CodeUnit.EOL_COMMENT;
        }

        int txId = program.startTransaction("Set comment");
        try {
            CodeUnit cu = program.getListing().getCodeUnitAt(address);
            if (cu != null) {
                cu.setComment(commentType, comment);
            }
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Delete a comment at an address.
     */
    public void deleteComment(String addressStr, String type) throws Exception {
        Program program = ctx.getProgram();
        Address address = ctx.parseAddress(addressStr);

        int txId = program.startTransaction("Delete comment");
        try {
            CodeUnit cu = program.getListing().getCodeUnitAt(address);
            if (cu != null) {
                if ("ALL".equals(type)) {
                    cu.setComment(CodeUnit.EOL_COMMENT, null);
                    cu.setComment(CodeUnit.PRE_COMMENT, null);
                    cu.setComment(CodeUnit.POST_COMMENT, null);
                    cu.setComment(CodeUnit.PLATE_COMMENT, null);
                    cu.setComment(CodeUnit.REPEATABLE_COMMENT, null);
                } else {
                    int commentType = getCommentType(type);
                    cu.setComment(commentType, null);
                }
            }
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * List comments in the program.
     */
    public List<GhidraEngine.CommentInfo> listComments(int offset, int limit, String type, String inFunction) {
        Program program = ctx.getProgram();
        List<GhidraEngine.CommentInfo> comments = new ArrayList<>();
        Listing listing = program.getListing();

        int[] commentTypes;
        String[] typeNames;

        if (type != null) {
            switch (type.toUpperCase()) {
                case "EOL": commentTypes = new int[]{CodeUnit.EOL_COMMENT}; typeNames = new String[]{"EOL"}; break;
                case "PRE": commentTypes = new int[]{CodeUnit.PRE_COMMENT}; typeNames = new String[]{"PRE"}; break;
                case "POST": commentTypes = new int[]{CodeUnit.POST_COMMENT}; typeNames = new String[]{"POST"}; break;
                case "PLATE": commentTypes = new int[]{CodeUnit.PLATE_COMMENT}; typeNames = new String[]{"PLATE"}; break;
                case "REPEATABLE": commentTypes = new int[]{CodeUnit.REPEATABLE_COMMENT}; typeNames = new String[]{"REPEATABLE"}; break;
                default:
                    commentTypes = new int[]{CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT,
                                             CodeUnit.PLATE_COMMENT, CodeUnit.REPEATABLE_COMMENT};
                    typeNames = new String[]{"EOL", "PRE", "POST", "PLATE", "REPEATABLE"};
            }
        } else {
            commentTypes = new int[]{CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT,
                                     CodeUnit.PLATE_COMMENT, CodeUnit.REPEATABLE_COMMENT};
            typeNames = new String[]{"EOL", "PRE", "POST", "PLATE", "REPEATABLE"};
        }

        int count = 0;
        int skipped = 0;

        AddressIterator addrIter = listing.getCommentAddressIterator(program.getMemory(), true);
        while (addrIter.hasNext() && count < limit) {
            Address addr = addrIter.next();

            // Filter by function
            if (inFunction != null) {
                Function func = program.getFunctionManager().getFunctionContaining(addr);
                if (func == null || !func.getName().equals(inFunction)) {
                    continue;
                }
            }

            CodeUnit cu = listing.getCodeUnitAt(addr);
            if (cu == null) continue;

            for (int i = 0; i < commentTypes.length; i++) {
                String comment = cu.getComment(commentTypes[i]);
                if (comment != null) {
                    if (skipped < offset) {
                        skipped++;
                        continue;
                    }

                    GhidraEngine.CommentInfo info = new GhidraEngine.CommentInfo();
                    info.address = addr.toString();
                    info.comment = comment;
                    info.type = typeNames[i];

                    Function func = program.getFunctionManager().getFunctionContaining(addr);
                    if (func != null) {
                        info.inFunction = func.getName();
                    }

                    comments.add(info);
                    count++;
                }
            }
        }

        return comments;
    }

    private int getCommentType(String type) {
        switch (type) {
            case "EOL": return CodeUnit.EOL_COMMENT;
            case "PRE": return CodeUnit.PRE_COMMENT;
            case "POST": return CodeUnit.POST_COMMENT;
            case "PLATE": return CodeUnit.PLATE_COMMENT;
            case "REPEATABLE": return CodeUnit.REPEATABLE_COMMENT;
            default: return CodeUnit.EOL_COMMENT;
        }
    }

    // ==================== BOOKMARKS ====================

    /**
     * Add a bookmark at an address.
     */
    public void addBookmark(String addressStr, String type, String category, String comment) throws Exception {
        Program program = ctx.getProgram();
        Address address = ctx.parseAddress(addressStr);
        BookmarkManager bmMgr = program.getBookmarkManager();

        int txId = program.startTransaction("Add bookmark");
        try {
            bmMgr.setBookmark(address, type, category, comment);
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Delete a bookmark at an address.
     */
    public void deleteBookmark(String addressStr, String type) throws Exception {
        Program program = ctx.getProgram();
        Address address = ctx.parseAddress(addressStr);
        BookmarkManager bmMgr = program.getBookmarkManager();

        int txId = program.startTransaction("Delete bookmark");
        try {
            // Get all bookmarks at the address
            Bookmark[] bookmarks = bmMgr.getBookmarks(address);
            for (Bookmark bm : bookmarks) {
                // If type is specified, only delete bookmarks of that type
                // If type is null, delete all bookmarks at the address
                if (type == null || type.equals(bm.getTypeString())) {
                    bmMgr.removeBookmark(bm);
                }
            }
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * List bookmarks in the program.
     */
    public List<GhidraEngine.BookmarkInfo> listBookmarks(int offset, int limit, String type, String category) {
        Program program = ctx.getProgram();
        List<GhidraEngine.BookmarkInfo> bookmarks = new ArrayList<>();
        BookmarkManager bmMgr = program.getBookmarkManager();

        int count = 0;
        int skipped = 0;

        Iterator<Bookmark> iter = bmMgr.getBookmarksIterator();
        while (iter.hasNext() && count < limit) {
            Bookmark bm = iter.next();

            // Filter by type
            if (type != null && !bm.getTypeString().equals(type)) {
                continue;
            }

            // Filter by category
            if (category != null && !bm.getCategory().equals(category)) {
                continue;
            }

            if (skipped < offset) {
                skipped++;
                continue;
            }

            GhidraEngine.BookmarkInfo info = new GhidraEngine.BookmarkInfo();
            info.address = bm.getAddress().toString();
            info.type = bm.getTypeString();
            info.category = bm.getCategory();
            info.comment = bm.getComment();

            Function func = program.getFunctionManager().getFunctionContaining(bm.getAddress());
            if (func != null) {
                info.inFunction = func.getName();
            }

            bookmarks.add(info);
            count++;
        }

        return bookmarks;
    }

    // ==================== LABELS ====================

    /**
     * Create a label at an address.
     */
    public void createLabel(String addressStr, String name, String namespace, boolean primary) throws Exception {
        Program program = ctx.getProgram();
        Address address = ctx.parseAddress(addressStr);
        SymbolTable symTable = program.getSymbolTable();

        int txId = program.startTransaction("Create label");
        try {
            Namespace ns = null;
            if (namespace != null) {
                ns = symTable.getNamespace(namespace, program.getGlobalNamespace());
                if (ns == null) {
                    ns = symTable.createNameSpace(program.getGlobalNamespace(), namespace, SourceType.USER_DEFINED);
                }
            } else {
                ns = program.getGlobalNamespace();
            }

            Symbol sym = symTable.createLabel(address, name, ns, SourceType.USER_DEFINED);
            if (primary && sym != null) {
                sym.setPrimary();
            }
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Delete a label at an address.
     */
    public void deleteLabel(String addressStr, String name) throws Exception {
        Program program = ctx.getProgram();
        Address address = ctx.parseAddress(addressStr);
        SymbolTable symTable = program.getSymbolTable();

        int txId = program.startTransaction("Delete label");
        try {
            if (name != null) {
                Symbol[] symbols = symTable.getSymbols(address);
                for (Symbol sym : symbols) {
                    if (sym.getName().equals(name)) {
                        sym.delete();
                        break;
                    }
                }
            } else {
                Symbol sym = symTable.getPrimarySymbol(address);
                if (sym != null && sym.getSymbolType() == SymbolType.LABEL) {
                    sym.delete();
                }
            }
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    // ==================== EQUATES ====================

    /**
     * List equates with filtering and pagination.
     */
    public GhidraEngine.ListEquatesResult listEquates(int offset, int limit, String filter, String regex, Long value) {
        Program program = ctx.getProgram();
        EquateTable equateTable = program.getEquateTable();
        Object[] filterArgs = GhidraContext.prepareFilter(filter, regex);
        String filterLower = (String) filterArgs[0];
        Pattern compiled = (Pattern) filterArgs[1];

        List<GhidraEngine.EquateInfo> page = new ArrayList<>();
        int total = 0;
        int skipped = 0;

        Iterator<Equate> iter = equateTable.getEquates();
        while (iter.hasNext()) {
            Equate eq = iter.next();

            if (!GhidraContext.passesFilter(eq.getName(), filterLower, compiled)) continue;
            if (value != null && eq.getValue() != value.longValue()) continue;

            total++;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (page.size() >= limit) continue; // continue to count total

            GhidraEngine.EquateInfo info = new GhidraEngine.EquateInfo();
            info.name = eq.getName();
            info.value = eq.getValue();
            info.hexValue = String.format("0x%x", eq.getValue());
            info.referenceCount = eq.getReferenceCount();
            info.references = new ArrayList<>();

            int refCount = 0;
            for (EquateReference eqRef : eq.getReferences()) {
                if (refCount >= 10) break;
                info.references.add(eqRef.getAddress().toString());
                refCount++;
            }

            page.add(info);
        }

        GhidraEngine.ListEquatesResult result = new GhidraEngine.ListEquatesResult();
        result.total = total;
        result.equates = page;
        return result;
    }

    /**
     * Set an equate at an instruction operand.
     */
    public void setEquate(String addressStr, int operandIndex, long value, String name) throws Exception {
        Program program = ctx.getProgram();
        Address addr = ctx.parseAddress(addressStr);
        if (addr == null) throw new Exception("Invalid address: " + addressStr);

        EquateTable equateTable = program.getEquateTable();
        int txId = program.startTransaction("Set equate " + name);
        try {
            Equate equate = equateTable.getEquate(name);
            if (equate == null) {
                equate = equateTable.createEquate(name, value);
            }
            equate.addReference(addr, operandIndex);
        } finally {
            program.endTransaction(txId, true);
        }
    }

    /**
     * Delete an equate reference at an instruction operand.
     */
    public void deleteEquate(String addressStr, int operandIndex, String name) throws Exception {
        Program program = ctx.getProgram();
        Address addr = ctx.parseAddress(addressStr);
        if (addr == null) throw new Exception("Invalid address: " + addressStr);

        EquateTable equateTable = program.getEquateTable();
        Equate equate = equateTable.getEquate(name);
        if (equate == null) throw new Exception("Equate not found: " + name);

        int txId = program.startTransaction("Delete equate reference " + name);
        try {
            equate.removeReference(addr, operandIndex);
            if (equate.getReferenceCount() == 0) {
                equateTable.removeEquate(name);
            }
        } finally {
            program.endTransaction(txId, true);
        }
    }

    // ==================== FUNCTION ATTRIBUTES ====================

    /**
     * Set function attributes (calling convention, noReturn, inline, varArgs).
     */
    public GhidraEngine.FunctionAttributesResult setFunctionAttributes(String address, String name,
            String callingConvention, Boolean noReturn, Boolean inline, Boolean varArgs) throws Exception {
        Program program = ctx.getProgram();
        Function func = getFunction(address, name);
        if (func == null) {
            throw new Exception("Function not found");
        }

        int txId = program.startTransaction("Set function attributes");
        try {
            if (callingConvention != null) {
                func.setCallingConvention(callingConvention);
            }
            if (noReturn != null) {
                func.setNoReturn(noReturn);
            }
            if (inline != null) {
                func.setInline(inline);
            }
            if (varArgs != null) {
                func.setVarArgs(varArgs);
            }
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }

        GhidraEngine.FunctionAttributesResult result = new GhidraEngine.FunctionAttributesResult();
        result.name = func.getName();
        result.address = func.getEntryPoint().toString();
        result.callingConvention = func.getCallingConventionName();
        result.noReturn = func.hasNoReturn();
        result.isInline = func.isInline();
        result.varArgs = func.hasVarArgs();
        return result;
    }

    // ==================== FUNCTION TAGS ====================

    /**
     * Add a tag to a function.
     */
    public List<String> addFunctionTag(String address, String name, String tag) throws Exception {
        Program program = ctx.getProgram();
        Function func = getFunction(address, name);
        if (func == null) {
            throw new Exception("Function not found");
        }

        int txId = program.startTransaction("Add function tag");
        try {
            func.addTag(tag);
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }

        return getFunctionTagNames(func);
    }

    /**
     * Remove a tag from a function.
     */
    public List<String> removeFunctionTag(String address, String name, String tag) throws Exception {
        Program program = ctx.getProgram();
        Function func = getFunction(address, name);
        if (func == null) {
            throw new Exception("Function not found");
        }

        int txId = program.startTransaction("Remove function tag");
        try {
            func.removeTag(tag);
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }

        return getFunctionTagNames(func);
    }

    /**
     * Get tag names for a function.
     */
    private List<String> getFunctionTagNames(Function func) {
        List<String> tagNames = new ArrayList<>();
        for (ghidra.program.model.listing.FunctionTag ft : func.getTags()) {
            tagNames.add(ft.getName());
        }
        return tagNames;
    }

    // ==================== BATCH TAG OPERATIONS ====================

    /**
     * Batch tag symbols (functions or data) with structured tags.
     * Tag format: "type" or "type:data" (e.g., "method:D2GameStrc" or "not-method")
     *
     * For functions: uses Ghidra's function tag system
     * For non-functions: uses bookmarks with category "StructuredTag"
     */
    public GhidraEngine.BatchTagResult batchTagSymbols(JsonArray operations) throws Exception {
        Program program = ctx.getProgram();
        GhidraEngine.BatchTagResult result = new GhidraEngine.BatchTagResult();
        result.success = true;
        result.applied = 0;

        int txId = program.startTransaction("Batch tag symbols");
        try {
            for (int i = 0; i < operations.size(); i++) {
                JsonObject op = operations.get(i).getAsJsonObject();
                String addressStr = op.get("address").getAsString();
                String action = op.get("action").getAsString();
                JsonObject tagObj = op.get("tag").getAsJsonObject();

                // Parse structured tag
                String tagType = tagObj.get("type").getAsString();
                String tagData = tagObj.has("data") ? tagObj.get("data").getAsString() : null;
                String tagString = tagData != null ? tagType + ":" + tagData : tagType;

                try {
                    Address addr = ctx.parseAddress(addressStr);
                    Function func = program.getFunctionManager().getFunctionAt(addr);

                    if (func != null) {
                        // Apply tag to function via function tag system
                        if ("add".equals(action)) {
                            func.addTag(tagString);
                        } else if ("remove".equals(action)) {
                            func.removeTag(tagString);
                        }
                    } else {
                        // Apply tag to non-function symbol via bookmark
                        BookmarkManager bookmarkMgr = program.getBookmarkManager();
                        if ("add".equals(action)) {
                            bookmarkMgr.setBookmark(addr, "StructuredTag", tagType, tagData != null ? tagData : "");
                        } else if ("remove".equals(action)) {
                            // Remove all bookmarks with matching type at this address
                            Bookmark[] bookmarks = bookmarkMgr.getBookmarks(addr);
                            for (Bookmark bm : bookmarks) {
                                if ("StructuredTag".equals(bm.getCategory()) && tagType.equals(bm.getType())) {
                                    bookmarkMgr.removeBookmark(bm);
                                }
                            }
                        }
                    }
                    result.applied++;
                } catch (Exception e) {
                    GhidraEngine.FailedTagOperation failure = new GhidraEngine.FailedTagOperation();
                    failure.address = addressStr;
                    failure.error = e.getMessage();
                    result.failed.add(failure);
                }
            }
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }

        return result;
    }

    // ==================== PRIVATE HELPERS ====================

    /**
     * Resolve a function by address or name.
     * Duplicated from GhidraEngine to avoid cross-ops dependency.
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
