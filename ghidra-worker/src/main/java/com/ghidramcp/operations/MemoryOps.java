package com.ghidramcp.operations;

import com.ghidramcp.GhidraContext;
import com.ghidramcp.GhidraEngine;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Memory, disassembly, cross-reference, segment, string, and data inspection operations.
 * Covers raw memory reads, disassembly, xrefs, segments, strings, data-at-address,
 * symbol-after, table detection, and global variable listing.
 */
public class MemoryOps {
    private final GhidraContext ctx;

    public MemoryOps(GhidraContext ctx) {
        this.ctx = ctx;
    }

    // ============== Raw memory ==============

    /**
     * Read raw bytes from memory at an address.
     */
    public byte[] readMemory(String addressStr, int length) throws Exception {
        Address address = ctx.parseAddress(addressStr);
        byte[] bytes = new byte[length];
        ctx.getProgram().getMemory().getBytes(address, bytes);
        return bytes;
    }

    // ============== Disassembly ==============

    /**
     * Get assembly instructions at an address with optional context before.
     */
    public List<GhidraEngine.DisassemblyLine> getDisassembly(String addressStr, int count, int context) throws Exception {
        List<GhidraEngine.DisassemblyLine> lines = new ArrayList<>();
        Address addr = ctx.parseAddress(addressStr);
        Program program = ctx.getProgram();

        Listing listing = program.getListing();
        int gathered = 0;

        // If context is specified, back up first
        if (context > 0) {
            Address backAddr = addr;
            for (int i = 0; i < context; i++) {
                Instruction prev = listing.getInstructionBefore(backAddr);
                if (prev != null) {
                    backAddr = prev.getAddress();
                } else {
                    break;
                }
            }
            addr = backAddr;
        }

        Instruction instr = listing.getInstructionAt(addr);
        if (instr == null) {
            instr = listing.getInstructionAfter(addr);
        }

        while (instr != null && gathered < count) {
            GhidraEngine.DisassemblyLine line = new GhidraEngine.DisassemblyLine();
            line.address = instr.getAddress().toString();
            line.mnemonic = instr.getMnemonicString();

            StringBuilder ops = new StringBuilder();
            for (int i = 0; i < instr.getNumOperands(); i++) {
                if (i > 0) ops.append(", ");
                ops.append(instr.getDefaultOperandRepresentation(i));
            }
            line.operands = ops.toString();

            // Get bytes
            byte[] bytes = instr.getBytes();
            StringBuilder hexBytes = new StringBuilder();
            for (byte b : bytes) {
                hexBytes.append(String.format("%02x ", b));
            }
            line.bytes = hexBytes.toString().trim();

            // Get comment
            String comment = instr.getComment(CodeUnit.EOL_COMMENT);
            if (comment != null) {
                line.comment = comment;
            }

            // Get containing function
            Function func = program.getFunctionManager().getFunctionContaining(instr.getAddress());
            if (func != null) {
                line.inFunction = func.getName();
            }

            lines.add(line);
            gathered++;
            instr = listing.getInstructionAfter(instr.getAddress());
        }

        return lines;
    }

    /**
     * Disassemble bytes at an address, creating code.
     */
    public int disassemble(String addressStr, int length) throws Exception {
        Address address = ctx.parseAddress(addressStr);
        Program program = ctx.getProgram();

        int txId = program.startTransaction("Disassemble");
        try {
            ghidra.app.cmd.disassemble.DisassembleCommand cmd;
            if (length > 0) {
                Address endAddr = address.add(length - 1);
                cmd = new ghidra.app.cmd.disassemble.DisassembleCommand(address, new AddressSet(address, endAddr), true);
            } else {
                cmd = new ghidra.app.cmd.disassemble.DisassembleCommand(address, null, true);
            }
            cmd.applyTo(program, ctx.getMonitor());
            program.endTransaction(txId, true);
            return (int) cmd.getDisassembledAddressSet().getNumAddresses();
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Clear code/data at an address range, returning it to undefined bytes.
     */
    public void clearListing(String startAddressStr, String endAddressStr) throws Exception {
        Program program = ctx.getProgram();
        Address startAddr = ctx.parseAddress(startAddressStr);
        Address endAddr = endAddressStr != null ? ctx.parseAddress(endAddressStr) : startAddr;

        int txId = program.startTransaction("Clear listing");
        try {
            program.getListing().clearCodeUnits(startAddr, endAddr, false);
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    // ============== Segments ==============

    /**
     * List memory segments/sections in the program.
     */
    public List<GhidraEngine.SegmentInfo> listSegments() {
        List<GhidraEngine.SegmentInfo> segments = new ArrayList<>();
        Memory mem = ctx.getProgram().getMemory();

        for (MemoryBlock block : mem.getBlocks()) {
            GhidraEngine.SegmentInfo info = new GhidraEngine.SegmentInfo();
            info.name = block.getName();
            info.start = block.getStart().toString();
            info.end = block.getEnd().toString();
            info.size = block.getSize();
            info.permissions = (block.isRead() ? "r" : "-") +
                              (block.isWrite() ? "w" : "-") +
                              (block.isExecute() ? "x" : "-");
            info.isInitialized = block.isInitialized();
            info.isVolatile = block.isVolatile();
            info.isMapped = block.isMapped();
            segments.add(info);
        }

        return segments;
    }

    // ============== Strings ==============

    /**
     * List string literals in the program with optional filtering.
     */
    public List<GhidraEngine.StringInfo> listStrings(int offset, int limit, int minLength, String filter, String regex) {
        List<GhidraEngine.StringInfo> strings = new ArrayList<>();
        Program program = ctx.getProgram();
        DataIterator iter = program.getListing().getDefinedData(true);
        Object[] filterArgs = GhidraContext.prepareFilter(filter, regex);
        String filterLower = (String) filterArgs[0];
        Pattern compiled = (Pattern) filterArgs[1];

        int count = 0;
        int skipped = 0;

        while (iter.hasNext() && count < limit) {
            Data data = iter.next();

            if (!data.hasStringValue()) continue;

            String value = (String) data.getValue();
            if (value == null || value.length() < minLength) continue;

            if (!GhidraContext.passesFilter(value, filterLower, compiled)) continue;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            GhidraEngine.StringInfo info = new GhidraEngine.StringInfo();
            info.address = data.getAddress().toString();
            info.value = value;
            info.length = value.length();
            info.encoding = data.getDataType().getName();

            // Get containing function
            Function func = program.getFunctionManager().getFunctionContaining(data.getAddress());
            if (func != null) {
                info.inFunction = func.getName();
            }

            // Get xref count
            info.xrefCount = program.getReferenceManager().getReferenceCountTo(data.getAddress());

            strings.add(info);
            count++;
        }

        return strings;
    }

    // ============== Cross-references ==============

    /**
     * Get cross-references to or from an address.
     */
    public List<GhidraEngine.XRef> getXrefs(String addressStr, String direction, int limit) {
        return getXrefs(addressStr, direction, limit, null);
    }

    /**
     * Get cross-references to or from an address with optional reference type filtering.
     */
    public List<GhidraEngine.XRef> getXrefs(String addressStr, String direction, int limit, List<String> refTypes) {
        List<GhidraEngine.XRef> xrefs = new ArrayList<>();
        Address address = ctx.parseAddress(addressStr);
        Program program = ctx.getProgram();
        ReferenceManager refMgr = program.getReferenceManager();
        Set<String> expandedTypes = refTypes != null ? expandRefTypeShortcuts(refTypes) : null;

        int count = 0;

        if (direction.equals("to") || direction.equals("both")) {
            for (Reference ref : refMgr.getReferencesTo(address)) {
                if (count >= limit) break;
                if (expandedTypes != null && !expandedTypes.contains(ref.getReferenceType().getName())) continue;
                xrefs.add(createXRef(ref, true));
                count++;
            }
        }

        if (direction.equals("from") || direction.equals("both")) {
            for (Reference ref : refMgr.getReferencesFrom(address)) {
                if (count >= limit) break;
                if (expandedTypes != null && !expandedTypes.contains(ref.getReferenceType().getName())) continue;
                xrefs.add(createXRef(ref, false));
                count++;
            }
        }

        return xrefs;
    }

    /**
     * Get cross-references with surrounding code context.
     */
    public List<GhidraEngine.XRefWithContext> getXrefsWithContext(String addressStr, String direction, int contextLines,
                                                                  String contextPattern, int limit) throws Exception {
        return getXrefsWithContext(addressStr, direction, contextLines, contextPattern, limit, null);
    }

    /**
     * Get cross-references with surrounding code context and optional reference type filtering.
     */
    public List<GhidraEngine.XRefWithContext> getXrefsWithContext(String addressStr, String direction, int contextLines,
                                                                  String contextPattern, int limit, List<String> refTypes) throws Exception {
        List<GhidraEngine.XRefWithContext> xrefs = new ArrayList<>();
        Address address = ctx.parseAddress(addressStr);
        Program program = ctx.getProgram();
        ReferenceManager refMgr = program.getReferenceManager();
        Listing listing = program.getListing();
        Set<String> expandedTypes = refTypes != null ? expandRefTypeShortcuts(refTypes) : null;

        int count = 0;

        if (direction.equals("to") || direction.equals("both")) {
            for (Reference ref : refMgr.getReferencesTo(address)) {
                if (count >= limit) break;
                if (expandedTypes != null && !expandedTypes.contains(ref.getReferenceType().getName())) continue;

                GhidraEngine.XRefWithContext xref = new GhidraEngine.XRefWithContext();
                xref.fromAddress = ref.getFromAddress().toString();
                xref.toAddress = ref.getToAddress().toString();
                xref.type = ref.getReferenceType().getName();
                xref.isCall = ref.getReferenceType().isCall();

                Function fromFunc = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (fromFunc != null) {
                    xref.fromFunction = fromFunc.getName();
                }

                // Get context lines around the reference
                xref.context = getContextLines(ref.getFromAddress(), contextLines, listing);

                // Filter by pattern if specified
                if (contextPattern != null) {
                    boolean matches = false;
                    for (String line : xref.context) {
                        if (line.matches(".*" + contextPattern + ".*")) {
                            matches = true;
                            break;
                        }
                    }
                    if (!matches) continue;
                }

                xrefs.add(xref);
                count++;
            }
        }

        if (direction.equals("from") || direction.equals("both")) {
            for (Reference ref : refMgr.getReferencesFrom(address)) {
                if (count >= limit) break;
                if (expandedTypes != null && !expandedTypes.contains(ref.getReferenceType().getName())) continue;

                GhidraEngine.XRefWithContext xref = new GhidraEngine.XRefWithContext();
                xref.fromAddress = ref.getFromAddress().toString();
                xref.toAddress = ref.getToAddress().toString();
                xref.type = ref.getReferenceType().getName();
                xref.isCall = ref.getReferenceType().isCall();

                Function toFunc = program.getFunctionManager().getFunctionContaining(ref.getToAddress());
                if (toFunc != null) {
                    xref.toFunction = toFunc.getName();
                }

                xref.context = getContextLines(ref.getFromAddress(), contextLines, listing);

                if (contextPattern != null) {
                    boolean matches = false;
                    for (String line : xref.context) {
                        if (line.matches(".*" + contextPattern + ".*")) {
                            matches = true;
                            break;
                        }
                    }
                    if (!matches) continue;
                }

                xrefs.add(xref);
                count++;
            }
        }

        return xrefs;
    }

    // ============== Data inspection ==============

    /**
     * Get detailed data information at an address including symbol, type, segment,
     * next symbol distance, xrefs, and pointer table pattern detection.
     */
    public Map<String, Object> getDataAtAddress(String addressStr, int lookAhead) throws Exception {
        Address address = ctx.parseAddress(addressStr);
        Program program = ctx.getProgram();
        Map<String, Object> result = new LinkedHashMap<>();

        // Symbol info
        Symbol sym = program.getSymbolTable().getPrimarySymbol(address);
        if (sym != null) {
            Map<String, Object> symInfo = new LinkedHashMap<>();
            symInfo.put("name", sym.getName());
            symInfo.put("fullPath", sym.getName(true));
            symInfo.put("type", sym.getSymbolType().toString());
            result.put("symbol", symInfo);
        }

        // All symbols at this address (including child labels under a struct symbol)
        Symbol[] allSyms = program.getSymbolTable().getSymbols(address);
        if (allSyms != null && allSyms.length > 0) {
            List<Map<String, Object>> overlapping = new ArrayList<>();
            for (Symbol s : allSyms) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", s.getName());
                entry.put("fullPath", s.getName(true));
                entry.put("type", s.getSymbolType().toString());
                entry.put("isPrimary", s.isPrimary());
                overlapping.add(entry);
            }
            result.put("overlappingSymbols", overlapping);
        }

        // Data info
        Data data = program.getListing().getDataAt(address);
        if (data != null) {
            Map<String, Object> dataInfo = new LinkedHashMap<>();
            dataInfo.put("type", data.getDataType().getName());
            dataInfo.put("size", data.getLength());
            if (data.hasStringValue()) {
                dataInfo.put("value", data.getValue().toString());
            }
            result.put("data", dataInfo);
        } else {
            // Inside a larger definition rather than at its start — say which one and where,
            // so the answer here matches what the symbol listing shows for this address.
            Data container = program.getListing().getDataContaining(address);
            if (container != null) {
                Map<String, Object> containerInfo = new LinkedHashMap<>();
                containerInfo.put("type", container.getDataType().getName());
                containerInfo.put("size", container.getLength());
                containerInfo.put("address", container.getAddress().toString());
                long delta = address.subtract(container.getAddress());
                containerInfo.put("offset", delta);
                Data component = container.getComponentContaining((int) delta);
                if (component != null) {
                    containerInfo.put("field", component.getFieldName());
                    containerInfo.put("fieldType", component.getDataType().getName());
                }
                result.put("containedIn", containerInfo);
            }
        }

        // Segment info
        MemoryBlock block = program.getMemory().getBlock(address);
        if (block != null) {
            Map<String, Object> segInfo = new LinkedHashMap<>();
            segInfo.put("name", block.getName());
            segInfo.put("readable", block.isRead());
            segInfo.put("writable", block.isWrite());
            segInfo.put("executable", block.isExecute());
            result.put("segment", segInfo);
        }

        // Next symbol — key for figuring out data size
        SymbolTable symTable = program.getSymbolTable();
        SymbolIterator symIter = symTable.getSymbolIterator(address.add(1), true);
        Address nextSymAddr = null;
        String nextSymName = null;
        while (symIter.hasNext()) {
            Symbol nextSym = symIter.next();
            if (!nextSym.isDynamic()) {
                nextSymAddr = nextSym.getAddress();
                nextSymName = nextSym.getName(true);
                break;
            }
        }
        if (nextSymAddr != null) {
            Map<String, Object> nextInfo = new LinkedHashMap<>();
            nextInfo.put("address", nextSymAddr.toString());
            nextInfo.put("name", nextSymName);
            nextInfo.put("distance", nextSymAddr.subtract(address));
            result.put("nextSymbol", nextInfo);
        }

        // Xrefs
        ReferenceManager refMgr = program.getReferenceManager();
        FunctionManager funcMgr = program.getFunctionManager();
        Map<String, Object> xrefInfo = new LinkedHashMap<>();
        List<String> xrefFuncs = new ArrayList<>();
        int xrefCount = 0;
        for (Reference ref : refMgr.getReferencesTo(address)) {
            xrefCount++;
            if (xrefFuncs.size() < 10) {
                Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                if (func != null) {
                    xrefFuncs.add(func.getName());
                }
            }
        }
        xrefInfo.put("count", xrefCount);
        xrefInfo.put("functions", xrefFuncs);
        result.put("xrefs", xrefInfo);

        // Pattern scan
        int scanLimit = lookAhead;
        if (scanLimit <= 0 && nextSymAddr != null) {
            scanLimit = (int) Math.min(nextSymAddr.subtract(address), 4096);
        }
        if (scanLimit <= 0) scanLimit = 256;
        if (scanLimit > 0) {
            int ptrSize = program.getDefaultPointerSize();
            int funcPtrCount = 0;
            int dataPtrCount = 0;
            try {
                for (int i = 0; i + ptrSize <= scanLimit; i += ptrSize) {
                    Address slot = address.add(i);
                    long value;
                    if (ptrSize == 4) {
                        value = program.getMemory().getInt(slot) & 0xFFFFFFFFL;
                    } else {
                        value = program.getMemory().getLong(slot);
                    }
                    if (value == 0) break;
                    Address target = address.getNewAddress(value);
                    if (funcMgr.getFunctionAt(target) != null) {
                        funcPtrCount++;
                    } else if (symTable.getPrimarySymbol(target) != null) {
                        dataPtrCount++;
                    } else {
                        break;
                    }
                }
            } catch (Exception ignored) {}
            Map<String, Object> pattern = new LinkedHashMap<>();
            if (funcPtrCount > 1) pattern.put("funcPtrArray", funcPtrCount);
            if (dataPtrCount > 1) pattern.put("dataPtrArray", dataPtrCount);
            if (!pattern.isEmpty()) result.put("pattern", pattern);
        }

        return result;
    }

    /**
     * Get the next N symbols after a given address.
     */
    public List<Map<String, Object>> getSymbolsAfter(String addressStr, int count) throws Exception {
        Address address = ctx.parseAddress(addressStr);
        Program program = ctx.getProgram();
        SymbolTable symTable = program.getSymbolTable();
        FunctionManager funcMgr = program.getFunctionManager();
        Listing listing = program.getListing();
        List<Map<String, Object>> symbols = new ArrayList<>();

        // One entry per address. Several names at one address are the same thing under
        // different labels — MSVC RTTI produces a flat "struct_X_RTTI_*" label alongside the
        // namespaced "X::RTTI_*" — so the extra names are folded in as aliases rather than
        // repeated as separate rows.
        Map<String, Map<String, Object>> byAddress = new LinkedHashMap<>();
        SymbolIterator iter = symTable.getSymbolIterator(address.add(1), true);
        while (iter.hasNext() && symbols.size() < count) {
            Symbol sym = iter.next();
            if (sym.isDynamic()) continue;

            Address symAddr = sym.getAddress();
            Map<String, Object> existing = byAddress.get(symAddr.toString());
            if (existing != null) {
                addAlias(existing, sym);
                continue;
            }

            Map<String, Object> info = new LinkedHashMap<>();
            info.put("address", symAddr.toString());
            info.put("name", sym.getName());
            info.put("fullName", sym.getName(true));
            info.put("symbolType", sym.getSymbolType().toString());
            info.put("distance", symAddr.subtract(address));

            Namespace ns = sym.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                info.put("namespace", ns.getName(true));
            }

            // Check if it's a function
            Function func = funcMgr.getFunctionAt(symAddr);
            if (func != null) {
                info.put("isFunction", true);
                info.put("functionSize", func.getBody().getNumAddresses());
                info.put("callingConvention", func.getCallingConventionName());
            }

            // Check if it has a defined data type
            Data data = listing.getDefinedDataAt(symAddr);
            if (data != null) {
                info.put("dataType", data.getDataType().getName());
                info.put("dataSize", data.getLength());
            }

            // Xref count
            int xrefCount = 0;
            for (Reference ref : program.getReferenceManager().getReferencesTo(symAddr)) {
                xrefCount++;
                if (xrefCount >= 1000) break; // cap counting
            }
            info.put("xrefCount", xrefCount);

            byAddress.put(symAddr.toString(), info);
            symbols.add(info);
        }

        return symbols;
    }

    /**
     * Record an additional name for an address already listed. The namespaced name is the
     * more useful one, so it takes over as the entry's name and the flat label becomes the
     * alias rather than the other way round.
     */
    @SuppressWarnings("unchecked")
    private void addAlias(Map<String, Object> entry, Symbol sym) {
        String current = (String) entry.get("name");
        String currentFull = (String) entry.get("fullName");
        String candidateFull = sym.getName(true);
        boolean candidateIsNamespaced = candidateFull.contains("::");
        boolean currentIsNamespaced = currentFull != null && currentFull.contains("::");

        String demoted;
        if (candidateIsNamespaced && !currentIsNamespaced) {
            entry.put("name", sym.getName());
            entry.put("fullName", candidateFull);
            Namespace ns = sym.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                entry.put("namespace", ns.getName(true));
            }
            demoted = current;
        } else {
            demoted = sym.getName();
        }

        List<String> aliases = (List<String>) entry.get("aliases");
        if (aliases == null) {
            aliases = new ArrayList<>();
            entry.put("aliases", aliases);
        }
        if (demoted != null && !aliases.contains(demoted)) {
            aliases.add(demoted);
        }
    }

    /**
     * Detect a pointer/data table at an address. Reads consecutive pointer-sized values
     * and resolves each to function, data, string, or unknown. Stops at NULL or non-pointer value.
     */
    public Map<String, Object> detectTable(String addressStr, int maxEntries, boolean applyType, String name) throws Exception {
        Address address = ctx.parseAddress(addressStr);
        Program program = ctx.getProgram();
        int ptrSize = program.getDefaultPointerSize();
        FunctionManager funcMgr = program.getFunctionManager();
        SymbolTable symTable = program.getSymbolTable();

        List<Map<String, Object>> entries = new ArrayList<>();
        for (int i = 0; i < maxEntries; i++) {
            Address slot = address.add((long) i * ptrSize);
            long value;
            try {
                if (ptrSize == 4) {
                    value = program.getMemory().getInt(slot) & 0xFFFFFFFFL;
                } else {
                    value = program.getMemory().getLong(slot);
                }
            } catch (Exception e) {
                break;
            }

            // NULL terminates
            if (value == 0) break;

            Address target = address.getNewAddress(value);
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("index", i);
            entry.put("address", slot.toString());
            entry.put("targetAddress", target.toString());

            Function func = funcMgr.getFunctionAt(target);
            if (func != null) {
                entry.put("targetType", "function");
                entry.put("targetName", func.getName());
            } else {
                Symbol sym = symTable.getPrimarySymbol(target);
                if (sym != null) {
                    // Check if it might be a string
                    Data d = program.getListing().getDataAt(target);
                    if (d != null && d.hasStringValue()) {
                        entry.put("targetType", "string");
                        entry.put("targetName", d.getValue().toString());
                    } else {
                        entry.put("targetType", "data");
                        entry.put("targetName", sym.getName());
                    }
                } else {
                    // Check if the value is even a valid address in the program
                    if (program.getMemory().contains(target)) {
                        entry.put("targetType", "unknown");
                    } else {
                        break; // Not a pointer — stop scanning
                    }
                }
            }

            entries.add(entry);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", address.toString());
        result.put("entryCount", entries.size());
        result.put("entries", entries);

        if (applyType && !entries.isEmpty()) {
            int txId = program.startTransaction("Detect table");
            try {
                int totalBytes = entries.size() * ptrSize;
                program.getListing().clearCodeUnits(address, address.add(totalBytes - 1), false);
                DataType ptrType = new PointerDataType(program.getDataTypeManager());
                DataType arrayType = new ArrayDataType(ptrType, entries.size(), ptrSize);
                program.getListing().createData(address, arrayType);
                if (name != null && !name.isEmpty()) {
                    Symbol sym = symTable.getPrimarySymbol(address);
                    if (sym != null) {
                        sym.setName(name, SourceType.USER_DEFINED);
                    }
                }
                program.endTransaction(txId, true);
                result.put("applied", true);
            } catch (Exception e) {
                program.endTransaction(txId, false);
                result.put("applied", false);
                result.put("error", e.getMessage());
            }
        }

        return result;
    }

    // ============== Global variables ==============

    /**
     * Get global variables (convenience wrapper).
     */
    public List<GhidraEngine.GlobalVariableInfo> getGlobalVariables(int offset, int limit, String filter) {
        return getGlobalVariablesWithTotal(offset, limit, filter, null, null, null, null).globals;
    }

    /**
     * List data symbols (global and namespaced) with type, size, xref count, and referencing functions.
     */
    public GhidraEngine.GlobalVariablesResult getGlobalVariablesWithTotal(int offset, int limit, String filter, String regex, String segment, String sortBy, String dataTypeFilter) {
        List<GhidraEngine.GlobalVariableInfo> globals = new ArrayList<>();
        Program program = ctx.getProgram();
        SymbolTable symTable = program.getSymbolTable();
        Listing listing = program.getListing();
        ReferenceManager refMgr = program.getReferenceManager();
        FunctionManager funcMgr = program.getFunctionManager();
        Memory memory = program.getMemory();
        Object[] filterArgs = GhidraContext.prepareFilter(filter, regex);
        String filterLower = (String) filterArgs[0];
        Pattern compiled = (Pattern) filterArgs[1];
        boolean sortByXrefs = "xrefs".equals(sortBy);

        int count = 0;
        int skipped = 0;
        int total = 0;

        for (Symbol sym : symTable.getAllSymbols(true)) {
            // Only include data symbols (globals)
            if (sym.getSymbolType() != SymbolType.LABEL) continue;

            // Skip function entry labels
            Address addr = sym.getAddress();
            if (funcMgr.getFunctionAt(addr) != null) continue;

            // Segment filter: check memory block name
            if (segment != null) {
                MemoryBlock block = memory.getBlock(addr);
                if (block == null || !block.getName().equals(segment)) continue;
            }

            // Check if it's actually data, not code
            Data data = listing.getDataAt(addr);
            if (data == null) {
                data = listing.getDataContaining(addr);
            }
            boolean hasExplicitData = (data != null);

            // If still no data, only include if it has references (skip orphan labels)
            if (!hasExplicitData && refMgr.getReferenceCountTo(addr) == 0) continue;

            // Skip if it's in an executable section (likely code, not data)
            if (!hasExplicitData) {
                MemoryBlock block = memory.getBlock(addr);
                if (block != null && block.isExecute() && !block.isWrite()) continue;
            }

            // Data type filter (case-insensitive substring match)
            if (dataTypeFilter != null) {
                if (!hasExplicitData) continue;
                if (!data.getDataType().getName().toLowerCase().contains(dataTypeFilter.toLowerCase())) continue;
            }

            String symName = sym.getName();
            if (!GhidraContext.passesFilter(symName, filterLower, compiled)) continue;

            total++;

            // When sorting, collect all matches; when streaming, paginate inline
            if (!sortByXrefs) {
                if (skipped < offset) {
                    skipped++;
                    continue;
                }
                if (count >= limit) continue;  // Continue to count total
            }

            GhidraEngine.GlobalVariableInfo info = new GhidraEngine.GlobalVariableInfo();
            info.name = symName;
            info.address = addr.toString();

            if (hasExplicitData) {
                info.dataType = data.getDataType().getName();
                info.size = data.getLength();
                info.isInitialized = data.isDefined();
            } else {
                // BSS / uninitialized symbol — infer from memory block
                MemoryBlock block = memory.getBlock(addr);
                info.dataType = "undefined";
                info.size = 1;
                info.isInitialized = (block != null && block.isInitialized());
            }

            // Get namespace (full path for proper folder structure)
            Namespace ns = sym.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                info.namespace = ns.getName(true);  // Full path
            }

            // Get xref count and referencing functions
            info.xrefCount = refMgr.getReferenceCountTo(addr);
            info.referencingFunctions = new ArrayList<>();

            for (Reference ref : refMgr.getReferencesTo(addr)) {
                Function refFunc = funcMgr.getFunctionContaining(ref.getFromAddress());
                if (refFunc != null) {
                    String funcName = refFunc.getName(true);  // Full name with namespace
                    if (!info.referencingFunctions.contains(funcName)) {
                        info.referencingFunctions.add(funcName);
                    }
                }
            }

            // Try to get value for simple types
            if (hasExplicitData) {
                try {
                    Object value = data.getValue();
                    if (value != null) {
                        info.value = value.toString();
                    }
                } catch (Exception e) {
                    // Ignore - some data types don't have simple values
                }
            }

            globals.add(info);
            count++;
        }

        // Sort by xrefs: collected all matches, now sort and paginate
        if (sortByXrefs && !globals.isEmpty()) {
            globals.sort((a, b) -> Integer.compare(b.xrefCount, a.xrefCount));
            int end = Math.min(offset + limit, globals.size());
            globals = offset < globals.size() ? new ArrayList<>(globals.subList(offset, end)) : new ArrayList<>();
        }

        return new GhidraEngine.GlobalVariablesResult(globals, total);
    }

    // ============== Private helpers ==============

    /**
     * Create an XRef DTO from a Ghidra Reference.
     */
    private GhidraEngine.XRef createXRef(Reference ref, boolean isTo) {
        Program program = ctx.getProgram();
        GhidraEngine.XRef xref = new GhidraEngine.XRef();
        xref.fromAddress = ref.getFromAddress().toString();
        xref.toAddress = ref.getToAddress().toString();
        xref.type = ref.getReferenceType().getName();
        xref.isCall = ref.getReferenceType().isCall();
        xref.isPrimary = ref.isPrimary();

        // Get containing functions
        Function fromFunc = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
        Function toFunc = program.getFunctionManager().getFunctionContaining(ref.getToAddress());

        if (fromFunc != null) xref.fromFunction = fromFunc.getName();
        if (toFunc != null) xref.toFunction = toFunc.getName();

        return xref;
    }

    /**
     * Expand reference type shortcuts into Ghidra RefType names.
     */
    private Set<String> expandRefTypeShortcuts(List<String> types) {
        Set<String> expanded = new HashSet<>();
        for (String t : types) {
            switch (t.toLowerCase()) {
                case "calls":
                    expanded.add("UNCONDITIONAL_CALL");
                    expanded.add("CONDITIONAL_CALL");
                    expanded.add("COMPUTED_CALL");
                    break;
                case "data":
                    expanded.add("DATA");
                    expanded.add("READ");
                    expanded.add("WRITE");
                    expanded.add("READ_WRITE");
                    break;
                case "jumps":
                    expanded.add("UNCONDITIONAL_JUMP");
                    expanded.add("CONDITIONAL_JUMP");
                    expanded.add("COMPUTED_JUMP");
                    break;
                case "reads":
                    expanded.add("READ");
                    expanded.add("READ_WRITE");
                    break;
                case "writes":
                    expanded.add("WRITE");
                    expanded.add("READ_WRITE");
                    break;
                default:
                    // Pass through exact Ghidra type names
                    expanded.add(t);
                    break;
            }
        }
        return expanded;
    }

    /**
     * Get context lines (assembly instructions) around a reference address.
     */
    private List<String> getContextLines(Address addr, int contextLines, Listing listing) {
        List<String> lines = new ArrayList<>();

        // Get instructions before
        Address cur = addr;
        List<String> beforeLines = new ArrayList<>();
        for (int i = 0; i < contextLines; i++) {
            Instruction prev = listing.getInstructionBefore(cur);
            if (prev == null) break;
            beforeLines.add(0, prev.getAddress() + ": " + prev.toString());
            cur = prev.getAddress();
        }
        lines.addAll(beforeLines);

        // Get the target instruction
        Instruction target = listing.getInstructionAt(addr);
        if (target != null) {
            lines.add(">>> " + target.getAddress() + ": " + target.toString());
        }

        // Get instructions after
        cur = addr;
        for (int i = 0; i < contextLines; i++) {
            Instruction next = listing.getInstructionAfter(cur);
            if (next == null) break;
            lines.add(next.getAddress() + ": " + next.toString());
            cur = next.getAddress();
        }

        return lines;
    }
}
