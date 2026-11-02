package com.ghidramcp;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A content hash of everything the generator reads, per function, per data type and per
 * global, computed from the program database with no decompile.
 *
 * <p>The change journal says what someone touched; these hashes say what is different. Two
 * states whose hashes agree for a symbol give the generator the same input for it, whatever
 * the journal said, so a record that was never written - a listener that missed it, an undo
 * that names nothing, a journal lost with its worker - cannot leave a consumer stale.
 *
 * <p>A function's hash covers its own state (qualified name and the kind of namespace it
 * sits in, body ranges and bytes, prototype with calling convention and storage, every
 * variable with type and storage, comments, labels, equates, instruction flow and
 * fall-through overrides, call-site signature overrides, tags, thunk target and call
 * fixup), the name and prototype of every function it references, the name and type of
 * every global it references, and the hash of every data type it names. A data type's hash
 * is its layout and names, recursing through anything embedded by value; a pointer
 * contributes its pointee's name only, since the pointee's layout does not change the code
 * that holds the pointer.
 *
 * <p>Must run where the program is open: over remote reads the same walk takes minutes.
 * Not thread-safe; build one per request.
 */
public final class StateHasher {
    private final Program program;
    private final Listing listing;
    private final Map<String, String> typeHashes = new HashMap<>();

    public StateHasher(Program program) {
        this.program = program;
        this.listing = program.getListing();
    }

    /** Address string -> hash, for every function, or only those starting at `only`. */
    public Map<String, String> functions(Collection<Address> only) {
        Map<String, String> out = new TreeMap<>();
        var fm = program.getFunctionManager();
        if (only != null) {
            for (Address a : only) {
                Function f = fm.getFunctionAt(a);
                if (f != null) out.put(a.toString(), function(f));
            }
            return out;
        }
        for (Function f : fm.getFunctions(true)) {
            out.put(f.getEntryPoint().toString(), function(f));
        }
        return out;
    }

    /** Path name -> hash, for every data type in the program's own manager. */
    public Map<String, String> dataTypes() {
        Map<String, String> out = new TreeMap<>();
        var it = program.getDataTypeManager().getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            out.put(dt.getPathName(), type(dt));
        }
        return out;
    }

    /**
     * Address string -> hash for every global: each defined data item outside a function
     * body, and each labelled address outside one that holds no defined data (a label on
     * undefined bytes is still a name the generator emits).
     */
    public Map<String, String> globals(Collection<Address> only) {
        Map<String, String> out = new TreeMap<>();
        var fm = program.getFunctionManager();
        if (only != null) {
            for (Address a : only) {
                String h = global(a);
                if (h != null) out.put(a.toString(), h);
            }
            return out;
        }
        var it = listing.getDefinedData(true);
        while (it.hasNext()) {
            Data d = it.next();
            if (fm.getFunctionContaining(d.getAddress()) != null) continue;
            out.put(d.getAddress().toString(), dataHash(d));
        }
        SymbolIterator syms = program.getSymbolTable().getPrimarySymbolIterator(program.getMemory(), true);
        while (syms.hasNext()) {
            Symbol s = syms.next();
            if (s.getSymbolType() != SymbolType.LABEL) continue;
            Address a = s.getAddress();
            if (out.containsKey(a.toString())) continue;
            if (fm.getFunctionContaining(a) != null) continue;
            Data d = listing.getDefinedDataAt(a);
            if (d != null) continue;
            out.put(a.toString(), labelHash(a));
        }
        return out;
    }

    private String global(Address a) {
        if (program.getFunctionManager().getFunctionContaining(a) != null) return null;
        Data d = listing.getDefinedDataAt(a);
        if (d != null) return dataHash(d);
        Symbol s = program.getSymbolTable().getPrimarySymbol(a);
        if (s != null && s.getSymbolType() == SymbolType.LABEL) return labelHash(a);
        return null;
    }

    private String dataHash(Data d) {
        StringBuilder sb = new StringBuilder();
        DataType dt = d.getDataType();
        sb.append(dt.getPathName()).append('|').append(type(dt)).append('|').append(d.getLength()).append('|');
        appendComments(sb, new AddressSet(d.getAddress(), d.getMaxAddress()));
        try {
            sb.append(hex(digest(d.getBytes())));
        } catch (MemoryAccessException e) {
            sb.append("uninit");
        }
        appendLabels(sb, d.getAddress());
        return hash(sb.toString());
    }

    private String labelHash(Address a) {
        StringBuilder sb = new StringBuilder("label|");
        appendComments(sb, new AddressSet(a));
        appendLabels(sb, a);
        return hash(sb.toString());
    }

    private void appendLabels(StringBuilder sb, Address a) {
        for (Symbol label : program.getSymbolTable().getSymbols(a)) {
            sb.append('|').append(label.getName(true)).append(label.isPrimary() ? "*" : "")
              .append(' ').append(namespaceKind(label.getParentNamespace()));
        }
    }

    public String function(Function f) {
        StringBuilder sb = new StringBuilder(512);
        sb.append(f.getName(true)).append(' ').append(namespaceKind(f.getParentNamespace())).append('\n');
        AddressSetView body = f.getBody();
        for (AddressRange r : body) sb.append(r.getMinAddress()).append('-').append(r.getMaxAddress()).append(',');
        sb.append('\n');
        try {
            for (AddressRange r : body) {
                byte[] b = new byte[(int) r.getLength()];
                program.getMemory().getBytes(r.getMinAddress(), b);
                sb.append(hex(digest(b)));
            }
        } catch (MemoryAccessException e) {
            sb.append("uninit");
        }
        sb.append('\n');

        sb.append(f.getCallingConventionName()).append('|').append(f.getPrototypeString(true, true)).append('|')
          .append(f.hasVarArgs()).append(f.isInline()).append(f.hasNoReturn()).append(f.hasCustomVariableStorage())
          .append(f.isExternal()).append('|').append(f.getStackPurgeSize()).append('|').append(f.getCallFixup())
          .append('|').append(f.getSignatureSource()).append('\n');
        Function thunked = f.getThunkedFunction(false);
        if (thunked != null) {
            sb.append("thunk ").append(thunked.getEntryPoint()).append(' ').append(thunked.getName(true)).append(' ')
              .append(thunked.getPrototypeString(true, true)).append('\n');
        }
        List<String> tags = new ArrayList<>();
        for (FunctionTag t : f.getTags()) tags.add(t.getName());
        Collections.sort(tags);
        sb.append(tags).append('\n');

        variable(sb, f.getReturn());
        for (Variable v : f.getAllVariables()) variable(sb, v);

        appendComments(sb, body);
        if (f.getComment() != null) sb.append("fc ").append(f.getComment()).append('\n');
        if (f.getRepeatableComment() != null) sb.append("frc ").append(f.getRepeatableComment()).append('\n');

        // Every symbol inside the body: labels, switch labels, and the call-site signature
        // overrides, whose prototype lives in a data type the label names.
        for (AddressRange r : body) {
            SymbolIterator it = program.getSymbolTable().getSymbolIterator(r.getMinAddress(), true);
            while (it.hasNext()) {
                Symbol s = it.next();
                if (s.getAddress().compareTo(r.getMaxAddress()) > 0) break;
                if (s.getSymbolType() == SymbolType.FUNCTION && s.getAddress().equals(f.getEntryPoint())) continue;
                sb.append("sym ").append(s.getAddress()).append(' ').append(s.getName(true))
                  .append(s.isPrimary() ? "*" : "").append('\n');
                DataTypeSymbol override = HighFunctionDBUtil.readOverride(s);
                if (override != null && override.getDataType() != null) {
                    sb.append("override ").append(type(override.getDataType())).append('\n');
                }
            }
        }
        AddressIterator eqs = program.getEquateTable().getEquateAddresses(body);
        while (eqs.hasNext()) {
            Address a = eqs.next();
            for (Equate e : program.getEquateTable().getEquates(a)) {
                sb.append("eq ").append(a).append(' ').append(e.getName()).append('=').append(e.getValue()).append('\n');
            }
        }

        // Flow edits that leave the bytes alone but change what the decompiler sees.
        for (Instruction ins : listing.getInstructions(body, true)) {
            FlowOverride fo = ins.getFlowOverride();
            if (fo != null && fo != FlowOverride.NONE) {
                sb.append("flow ").append(ins.getAddress()).append(' ').append(fo).append('\n');
            }
            if (ins.isFallThroughOverridden()) {
                sb.append("fall ").append(ins.getAddress()).append(' ').append(ins.getFallThrough()).append('\n');
            }
        }

        // References out of the body, with what each one lands on as the generator sees it.
        AddressIterator src = program.getReferenceManager().getReferenceSourceIterator(body, true);
        while (src.hasNext()) {
            Address a = src.next();
            for (Reference ref : program.getReferenceManager().getReferencesFrom(a)) {
                Address to = ref.getToAddress();
                sb.append("ref ").append(a).append(' ').append(ref.getOperandIndex()).append(' ')
                  .append(ref.getReferenceType()).append(' ').append(ref.isPrimary()).append(' ')
                  .append(ref.getSource()).append(' ').append(to);
                if (to.isMemoryAddress() || to.isExternalAddress()) {
                    Function callee = program.getFunctionManager().getFunctionAt(to);
                    if (callee != null) {
                        sb.append(" fn ").append(callee.getName(true)).append(' ')
                          .append(callee.getCallingConventionName()).append(' ')
                          .append(callee.getPrototypeString(true, true)).append(callee.hasNoReturn())
                          .append(callee.hasVarArgs());
                    } else {
                        Symbol s = program.getSymbolTable().getPrimarySymbol(to);
                        if (s != null) sb.append(" sym ").append(s.getName(true));
                        Data d = listing.getDataContaining(to);
                        if (d != null && d.isDefined()) {
                            sb.append(" data ").append(d.getAddress()).append(' ').append(d.getDataType().getPathName())
                              .append(' ').append(type(d.getDataType()));
                            Symbol ds = d.getPrimarySymbol();
                            if (ds != null) sb.append(' ').append(ds.getName(true));
                        }
                    }
                }
                sb.append('\n');
            }
        }
        return hash(sb.toString());
    }

    /** A function moved into a class emits differently from one in a plain namespace. */
    private static String namespaceKind(Namespace ns) {
        if (ns == null || ns.isGlobal()) return "global";
        Symbol s = ns.getSymbol();
        return s == null ? "?" : s.getSymbolType().toString();
    }

    private void variable(StringBuilder sb, Variable v) {
        if (v == null) return;
        DataType dt = v.getDataType();
        sb.append("var ").append(v.getName()).append(' ').append(dt == null ? "-" : dt.getPathName()).append(' ')
          .append(dt == null ? "-" : type(dt)).append(' ').append(v.getVariableStorage()).append(' ')
          .append(v.getFirstUseOffset()).append(' ').append(v.getSource()).append(' ').append(v.getComment()).append('\n');
    }

    private void appendComments(StringBuilder sb, AddressSetView set) {
        AddressIterator it = listing.getCommentAddressIterator(set, true);
        while (it.hasNext()) {
            Address a = it.next();
            for (CommentType t : CommentType.values()) {
                String c = listing.getComment(t, a);
                if (c != null) sb.append("c ").append(a).append(' ').append(t).append(' ').append(c).append('\n');
            }
        }
    }

    /** Layout and names, recursing through by-value members; pointers stop at the name. */
    public String type(DataType dt) {
        String key = dt.getClass().getName() + ' ' + dt.getPathName() + ' ' + dt.getLength();
        String cached = typeHashes.get(key);
        if (cached != null) return cached;
        // A by-value cycle cannot exist, but a broken database should not hang the worker.
        typeHashes.put(key, "cycle:" + dt.getPathName());
        StringBuilder sb = new StringBuilder();
        sb.append(dt.getClass().getSimpleName()).append(' ').append(dt.getPathName()).append(' ').append(dt.getLength())
          .append(' ').append(dt.getAlignment()).append(' ').append(dt.getDescription()).append('\n');
        if (dt instanceof Pointer p) {
            DataType to = p.getDataType();
            sb.append("-> ").append(to == null ? "void" : to.getPathName());
        } else if (dt instanceof Array a) {
            sb.append(a.getNumElements()).append(" x ").append(type(a.getDataType()));
        } else if (dt instanceof TypeDef t) {
            sb.append("= ").append(type(t.getDataType()));
        } else if (dt instanceof Enum e) {
            for (String n : e.getNames()) {
                sb.append(n).append('=').append(e.getValue(n)).append(' ').append(e.getComment(n)).append(';');
            }
        } else if (dt instanceof FunctionDefinition fd) {
            sb.append(fd.getPrototypeString(true)).append(' ').append(fd.getCallingConventionName())
              .append(fd.hasVarArgs()).append(fd.hasNoReturn());
        } else if (dt instanceof Composite c) {
            sb.append(c.isPackingEnabled()).append(' ').append(c.getExplicitPackingValue()).append(' ')
              .append(c.getExplicitMinimumAlignment()).append('\n');
            for (DataTypeComponent m : c.getDefinedComponents()) {
                DataType mt = m.getDataType();
                sb.append(m.getOffset()).append(' ').append(m.getLength()).append(' ').append(m.getFieldName()).append(' ')
                  .append(m.getComment()).append(' ');
                if (mt instanceof BitFieldDataType bf) {
                    sb.append("bf ").append(bf.getBitOffset()).append(':').append(bf.getBitSize()).append(' ')
                      .append(type(bf.getBaseDataType()));
                } else {
                    sb.append(type(mt));
                }
                sb.append('\n');
            }
        }
        String h = hash(sb.toString());
        typeHashes.put(key, h);
        return h;
    }

    private static byte[] digest(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String hash(String s) {
        return hex(digest(s.getBytes(StandardCharsets.UTF_8))).substring(0, 24);
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }
}
