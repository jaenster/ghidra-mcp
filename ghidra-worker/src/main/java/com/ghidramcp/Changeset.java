package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * apply_changeset: a list of Ghidra edits (the Redivivus proposal ops, without `program`) applied
 * as exactly one transaction, all or nothing.
 *
 * One transaction is opened under the caller's description. Inside it every op's `expect` is
 * checked against the program first, through the same views a proposal was checked with
 * (get_function_info, get_data_at_address, get_data_type), and only when all of them hold is any
 * op applied. Each op is applied by the existing tool's code (rename_symbol, set_function_variable_*,
 * set_prototype, set_data_type, update_structure); those open their own transactions, which Ghidra
 * nests inside the open one, so the undo history and the change journal see one transaction. Any
 * mismatch or failure ends the transaction with commit=false and nothing is left behind. A dry run
 * does the same work and always rolls back. Nothing is checked in: the caller commits separately.
 *
 * The comparisons are the proposal checker's (redivivus-app src/proposals/check.ts), through
 * ProposalNorm; review rules (house naming, which names may be replaced) are the checker's job and
 * are not repeated here.
 */
public class Changeset {
    private static final int MAX_OPS = 20;
    private static final int MAX_DESCRIPTION = 500;

    private final CommandHandler handler;
    private final GhidraEngine engine;
    private final Logger log;

    public Changeset(CommandHandler handler, Logger log) {
        this.handler = handler;
        this.engine = handler.engine();
        this.log = log;
    }

    /** One parsed op. */
    private static final class Op {
        int index;
        String kind;
        JsonObject raw;
        String address;      // rename_function, rename_global, set_prototype, set_global_type
        String function;     // rename_local, retype_local
        String storage;      // rename_local, retype_local (normalised)
        String typePath;     // struct_field
        int offset;          // struct_field
        String name;         // new name
        String type;         // new type
        String signature;
        String callingConvention;
        JsonObject expect;
        // Resolved by the check.
        String varName;      // the variable the op targets (rename_local, retype_local)
        JsonObject dataType; // struct_field: the get_data_type view
        JsonObject field;    // struct_field: the field
        JsonObject before;
    }

    public JsonObject apply(JsonObject params) throws Exception {
        if (engine.isReadOnly()) {
            throw new Exception("apply_changeset: this session is read-only (or follows the latest "
                + "server version); open a writable session to apply a changeset");
        }
        Program program = engine.getProgram();
        if (program == null) throw new Exception("apply_changeset: no program is open");

        String description = params.has("description") && params.get("description").isJsonPrimitive()
            ? ProposalNorm.jsTrim(params.get("description").getAsString()) : "";
        if (description.isEmpty()) throw new IllegalArgumentException("description is required (the transaction's name)");
        if (description.length() > MAX_DESCRIPTION) {
            throw new IllegalArgumentException("description: at most " + MAX_DESCRIPTION + " characters");
        }
        boolean dryRun = params.has("dryRun") && params.get("dryRun").isJsonPrimitive()
            && params.get("dryRun").getAsBoolean();
        if (!params.has("ops") || !params.get("ops").isJsonArray()) {
            throw new IllegalArgumentException("ops is required: an array of 1-" + MAX_OPS + " ops");
        }
        JsonArray rawOps = params.getAsJsonArray("ops");

        JsonObject result = new JsonObject();
        result.addProperty("ok", false);
        result.addProperty("dryRun", dryRun);
        result.addProperty("description", description);
        result.add("applied", new JsonArray());

        // Shape first: a malformed changeset never opens a transaction.
        JsonArray errors = new JsonArray();
        if (rawOps.size() < 1 || rawOps.size() > MAX_OPS) {
            errors.add(opError(-1, "(changeset)", List.of("ops: 1 to " + MAX_OPS + " ops, got " + rawOps.size())));
        }
        List<Op> ops = new ArrayList<>();
        for (int i = 0; i < rawOps.size(); i++) {
            List<String> errs = new ArrayList<>();
            Op op = parse(i, rawOps.get(i), errs);
            if (!errs.isEmpty()) errors.add(opError(i, op.kind, errs));
            ops.add(op);
        }
        Map<String, Integer> targets = new HashMap<>();
        for (Op op : ops) {
            if (op.kind == null || errors.size() > 0) continue;
            String key = targetKey(op);
            Integer first = targets.putIfAbsent(key, op.index);
            if (first != null) {
                errors.add(opError(op.index, op.kind,
                    List.of("changes the same thing as ops[" + first + "]; merge them into one op")));
            }
        }
        if (errors.size() > 0) {
            result.add("errors", errors);
            return result;
        }

        int txId = program.startTransaction(description);
        boolean commit = false;
        try {
            TransactionInfo tx = program.getCurrentTransactionInfo();
            long transactionId = tx != null ? tx.getID() : -1;

            // Every expect, before anything changes.
            for (Op op : ops) {
                List<String> errs = new ArrayList<>();
                try {
                    check(op, errs);
                } catch (Exception e) {
                    errs.add(message(e));
                }
                if (!errs.isEmpty()) errors.add(opError(op.index, op.kind, errs));
            }
            if (errors.size() > 0) {
                result.add("errors", errors);
                return result;
            }

            JsonArray applied = new JsonArray();
            for (Op op : ops) {
                try {
                    applyOp(op);
                    engine.invalidateCache();
                    JsonObject entry = new JsonObject();
                    entry.addProperty("index", op.index);
                    entry.addProperty("op", op.kind);
                    entry.add("before", op.before);
                    entry.add("after", view(op));
                    applied.add(entry);
                } catch (Exception e) {
                    errors.add(opError(op.index, op.kind, List.of(message(e))));
                    result.add("errors", errors);
                    return result;
                }
            }

            result.add("applied", applied);
            result.addProperty("ok", true);
            if (!dryRun) {
                commit = true;
                if (transactionId >= 0) result.addProperty("transactionId", transactionId);
            }
            return result;
        } finally {
            boolean ended = program.endTransaction(txId, commit);
            engine.invalidateCache();
            log.info("apply_changeset \"" + description + "\": " + (commit ? "committed" : "rolled back")
                + " (" + ops.size() + " ops, endTransaction=" + ended + ")");
        }
    }

    // ---------------------------------------------------------------- parsing

    private Op parse(int index, JsonElement el, List<String> errs) {
        Op op = new Op();
        op.index = index;
        if (el == null || !el.isJsonObject()) {
            op.kind = "(not an object)";
            errs.add("an op is an object like {\"op\": \"rename_function\", ...}");
            return op;
        }
        JsonObject o = el.getAsJsonObject();
        op.raw = o;
        String kind = str(o, "op");
        op.kind = kind;
        Set<String> allowed = new LinkedHashSet<>();
        allowed.add("op");
        allowed.add("expect");
        Set<String> expectKeys = new LinkedHashSet<>();
        if (kind == null) {
            errs.add("op must be one of rename_function, rename_global, rename_local, retype_local, "
                + "set_prototype, set_global_type, struct_field");
            return op;
        }
        switch (kind) {
            case "rename_function":
            case "rename_global":
                allowed.add("address"); allowed.add("name");
                expectKeys.add("name");
                op.address = address(o, "address", errs);
                op.name = ident(o, "name", errs, true);
                break;
            case "rename_local":
            case "retype_local":
                allowed.add("function"); allowed.add("storage");
                op.function = address(o, "function", errs);
                String storage = str(o, "storage");
                if (storage == null || !ProposalNorm.STORAGE.matcher(ProposalNorm.jsTrim(storage)).matches()) {
                    errs.add("storage is a stack offset like \"Stack[-0x10]\" or a register like \"ECX\", as get_function_info shows it");
                } else {
                    op.storage = ProposalNorm.normStorage(storage);
                }
                if (kind.equals("rename_local")) {
                    allowed.add("name");
                    expectKeys.add("name");
                    op.name = ident(o, "name", errs, true);
                } else {
                    allowed.add("type");
                    expectKeys.add("type");
                    op.type = typeString(o, "type", errs, true);
                }
                break;
            case "set_prototype": {
                allowed.add("address"); allowed.add("signature"); allowed.add("callingConvention");
                expectKeys.add("signature"); expectKeys.add("callingConvention");
                op.address = address(o, "address", errs);
                String sig = str(o, "signature");
                if (sig == null || ProposalNorm.jsTrim(sig).length() < 3 || ProposalNorm.jsTrim(sig).length() > 2000
                        || !ProposalNorm.SIGNATURE.matcher(ProposalNorm.jsTrim(sig)).matches()) {
                    errs.add("signature looks like \"int ITEMS_GetQuality(D2UnitStrc * pItem)\"");
                } else {
                    op.signature = ProposalNorm.jsTrim(sig);
                }
                String cc = str(o, "callingConvention");
                if (cc == null || !ProposalNorm.CALLING_CONVENTION.matcher(ProposalNorm.jsTrim(cc)).matches()) {
                    errs.add("a calling convention is written like \"__stdcall\" or \"__fastcall\"");
                } else {
                    op.callingConvention = ProposalNorm.jsTrim(cc);
                }
                break;
            }
            case "set_global_type":
                allowed.add("address"); allowed.add("type");
                expectKeys.add("type"); expectKeys.add("size");
                op.address = address(o, "address", errs);
                op.type = typeString(o, "type", errs, true);
                break;
            case "struct_field": {
                allowed.add("typePath"); allowed.add("offset"); allowed.add("name"); allowed.add("type");
                expectKeys.add("name"); expectKeys.add("type"); expectKeys.add("defHash");
                String tp = str(o, "typePath");
                if (tp == null || ProposalNorm.jsTrim(tp).isEmpty() || ProposalNorm.jsTrim(tp).length() > 300
                        || !ProposalNorm.TYPE_PATH.matcher(ProposalNorm.jsTrim(tp)).matches()) {
                    errs.add("a type path is \"D2UnitStrc\" or \"/Category/D2UnitStrc\"");
                } else {
                    op.typePath = ProposalNorm.jsTrim(tp);
                }
                op.offset = offset(o, errs);
                op.name = ident(o, "name", errs, false);
                op.type = typeString(o, "type", errs, false);
                if (op.name == null && op.type == null && !o.has("name") && !o.has("type")) {
                    errs.add("struct_field needs a new name, a new type, or both");
                }
                break;
            }
            default:
                errs.add("op must be one of rename_function, rename_global, rename_local, retype_local, "
                    + "set_prototype, set_global_type, struct_field (comments, deletes and new functions or structs are not changesets)");
                return op;
        }
        for (String k : o.keySet()) {
            if (!allowed.contains(k)) {
                errs.add(k.equals("program")
                    ? "program: not part of a changeset op; the session decides the program"
                    : "unknown field \"" + k + "\"");
            }
        }
        JsonElement ex = o.get("expect");
        if (ex == null || !ex.isJsonObject()) {
            errs.add("expect is required: {" + String.join(", ", expectKeys) + "} as you saw it");
            return op;
        }
        op.expect = ex.getAsJsonObject();
        for (String k : op.expect.keySet()) {
            if (!expectKeys.contains(k)) errs.add("expect: unknown field \"" + k + "\"");
        }
        for (String k : expectKeys) {
            JsonElement v = op.expect.get(k);
            if (k.equals("size")) {
                if (v == null || !v.isJsonPrimitive() || !v.getAsJsonPrimitive().isNumber()
                        || v.getAsDouble() != Math.floor(v.getAsDouble()) || v.getAsDouble() < 0) {
                    errs.add("expect.size is a whole number of bytes");
                }
            } else if (v == null || !v.isJsonPrimitive() || !v.getAsJsonPrimitive().isString() || v.getAsString().isEmpty()) {
                errs.add("expect." + k + " is required (a non-empty string)");
            } else if (k.equals("defHash") && !ProposalNorm.DEF_HASH.matcher(ProposalNorm.jsTrim(v.getAsString())).matches()) {
                errs.add("defHash is 16 lowercase hex digits");
            }
        }
        return op;
    }

    private static String targetKey(Op o) {
        switch (o.kind) {
            case "rename_function": return "fn-name:" + o.address;
            case "set_prototype": return "fn-proto:" + o.address;
            case "rename_global": return "global-name:" + o.address;
            case "set_global_type": return "global-type:" + o.address;
            case "rename_local": return "local-name:" + o.function + ":" + o.storage;
            case "retype_local": return "local-type:" + o.function + ":" + o.storage;
            default: return "field:" + o.typePath.replaceFirst("^/+", "") + ":" + o.offset;
        }
    }

    private static String str(JsonObject o, String key) {
        JsonElement v = o.get(key);
        return v != null && v.isJsonPrimitive() && v.getAsJsonPrimitive().isString() ? v.getAsString() : null;
    }

    private static String address(JsonObject o, String key, List<String> errs) {
        String s = str(o, key);
        if (s == null || !ProposalNorm.ADDRESS.matcher(ProposalNorm.jsTrim(s)).matches()) {
            errs.add(key + ": an address is hex, like \"0x00401000\"");
            return null;
        }
        return ProposalNorm.normAddress(s);
    }

    private static String ident(JsonObject o, String key, List<String> errs, boolean required) {
        if (!o.has(key)) {
            if (required) errs.add(key + " is required");
            return null;
        }
        String s = str(o, key);
        String t = s == null ? null : ProposalNorm.jsTrim(s);
        if (t == null || t.isEmpty() || t.length() > 128 || !ProposalNorm.IDENT.matcher(t).matches()) {
            errs.add(key + ": a name is a C identifier: letters, digits and _");
            return null;
        }
        return t;
    }

    private static String typeString(JsonObject o, String key, List<String> errs, boolean required) {
        if (!o.has(key)) {
            if (required) errs.add(key + " is required");
            return null;
        }
        String s = str(o, key);
        String t = s == null ? null : ProposalNorm.jsTrim(s);
        if (t == null || t.isEmpty() || t.length() > 200 || !ProposalNorm.TYPE.matcher(t).matches()) {
            errs.add(key + ": a type is written as Ghidra shows it, like \"D2UnitStrc *\" or \"char[16]\"");
            return null;
        }
        return t;
    }

    private static int offset(JsonObject o, List<String> errs) {
        JsonElement v = o.get("offset");
        if (v != null && v.isJsonPrimitive()) {
            JsonPrimitive p = v.getAsJsonPrimitive();
            if (p.isNumber()) {
                double d = p.getAsDouble();
                if (d == Math.floor(d) && d >= 0 && d <= 0x1000000) return (int) d;
            } else if (p.isString()) {
                String s = ProposalNorm.jsTrim(p.getAsString());
                if (s.matches("^(0x[0-9a-fA-F]+|\\d+)$")) {
                    long n = s.startsWith("0x") ? Long.parseLong(s.substring(2), 16) : Long.parseLong(s);
                    if (n <= Integer.MAX_VALUE) return (int) n;
                }
            }
        }
        errs.add("offset is a byte offset, a number or \"0x10\"");
        return -1;
    }

    // ---------------------------------------------------------------- reads (the checker's views)

    private JsonObject read(String command, JsonObject args) throws Exception {
        return handler.handle(command, args);
    }

    private static JsonObject args(String... kv) {
        JsonObject a = new JsonObject();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            if (kv[i + 1] != null) a.addProperty(kv[i], kv[i + 1]);
        }
        return a;
    }

    private static String s(JsonObject o, String key) {
        if (o == null) return null;
        JsonElement v = o.get(key);
        return v == null || v.isJsonNull() ? null : v.getAsString();
    }

    private static JsonObject obj(JsonObject o, String key) {
        if (o == null) return null;
        JsonElement v = o.get(key);
        return v != null && v.isJsonObject() ? v.getAsJsonObject() : null;
    }

    private static String q(String v) {
        if (v == null) return "null";
        StringBuilder sb = new StringBuilder();
        ProposalNorm.quote(sb, v);
        return sb.toString();
    }

    private static String expectStr(Op op, String key) {
        return ProposalNorm.jsTrim(op.expect.get(key).getAsString());
    }

    /** The function at an entry address, or null with the reason. */
    private JsonObject fn(String address, List<String> errs, String what) {
        JsonObject fi;
        try {
            fi = read("get_function_info", args("address", address));
        } catch (Exception e) {
            errs.add(what + " " + address + ": no function there (" + message(e) + ")");
            return null;
        }
        String entry = s(fi, "entryPoint") != null ? s(fi, "entryPoint") : s(fi, "address");
        if (!ProposalNorm.addrEq(entry, address)) {
            errs.add(what + " " + address + " is inside " + (s(fi, "name") != null ? s(fi, "name") : "a function")
                + ", whose entry is 0x" + String.valueOf(entry).replaceFirst("^(?i)0x", "") + "; give the entry address");
            return null;
        }
        return fi;
    }

    /** The global whose symbol starts at an address, or null with the reason. */
    private JsonObject data(String address, List<String> errs) {
        JsonObject d;
        try {
            d = read("get_data_at_address", args("address", address));
        } catch (Exception e) {
            errs.add("address " + address + ": nothing readable there (" + message(e) + ")");
            return null;
        }
        JsonObject sym = obj(d, "symbol");
        if (sym == null || s(sym, "name") == null || s(sym, "name").isEmpty()) {
            JsonObject in = obj(d, "containedIn");
            String inside = in != null ? " it is inside the " + s(in, "type") + " at 0x" + s(in, "address") : "";
            errs.add("address " + address + ": no symbol starts there;" + (inside.isEmpty() ? " give the address of the global itself" : inside));
            return null;
        }
        JsonObject seg = obj(d, "segment");
        boolean executable = seg != null && seg.has("executable") && seg.get("executable").isJsonPrimitive()
            && seg.get("executable").getAsJsonPrimitive().isBoolean() && seg.get("executable").getAsBoolean();
        if ("Function".equals(s(sym, "type")) || (executable && !d.has("data"))) {
            errs.add("address " + address + " is code, not a global; use rename_function or set_prototype");
            return null;
        }
        return d;
    }

    /** Parameters then locals, each with its storage normalised. */
    private static List<JsonObject> variables(JsonObject fi) {
        List<JsonObject> vars = new ArrayList<>();
        for (String list : new String[] {"parameters", "localVariables"}) {
            JsonElement l = fi.get(list);
            if (l == null || !l.isJsonArray()) continue;
            for (JsonElement e : l.getAsJsonArray()) {
                if (!e.isJsonObject()) continue;
                JsonObject v = e.getAsJsonObject();
                JsonElement name = v.get("name");
                if (name == null || !name.isJsonPrimitive() || !name.getAsJsonPrimitive().isString()) continue;
                JsonObject c = new JsonObject();
                c.addProperty("name", name.getAsString());
                c.addProperty("dataType", s(v, "dataType") == null ? "" : s(v, "dataType"));
                JsonElement rt = v.get("resolvedType");
                c.add("resolvedType", rt != null && rt.isJsonPrimitive() && rt.getAsJsonPrimitive().isString() ? rt : JsonNull.INSTANCE);
                c.addProperty("storage", ProposalNorm.normStorage(s(v, "storage") == null ? "" : s(v, "storage")));
                c.addProperty("isParameter", list.equals("parameters"));
                vars.add(c);
            }
        }
        return vars;
    }

    private JsonObject structView(Op op, List<String> errs) throws Exception {
        String[] parts = op.typePath.split("/");
        List<String> segs = new ArrayList<>();
        for (String p : parts) if (!p.isEmpty()) segs.add(p);
        String name = segs.remove(segs.size() - 1);
        String category = segs.isEmpty() ? null : "/" + String.join("/", segs);
        try {
            return read("get_data_type", args("name", name, "category", category));
        } catch (Exception e) {
            errs.add("typePath " + q(op.typePath) + ": no such type in this program");
            return null;
        }
    }

    // ---------------------------------------------------------------- checks

    private void check(Op op, List<String> errs) throws Exception {
        switch (op.kind) {
            case "rename_function": {
                JsonObject fi = fn(op.address, errs, "address");
                if (fi == null) return;
                op.before = new JsonObject();
                op.before.addProperty("name", s(fi, "name"));
                op.before.add("namespace", fi.has("namespace") ? fi.get("namespace") : JsonNull.INSTANCE);
                if (!expectStr(op, "name").equals(s(fi, "name"))) {
                    errs.add("expect.name is " + q(op.expect.get("name").getAsString()) + " but the function is named " + q(s(fi, "name")) + " now");
                }
                return;
            }
            case "rename_global": {
                JsonObject d = data(op.address, errs);
                if (d == null) return;
                String name = s(obj(d, "symbol"), "name");
                op.before = new JsonObject();
                op.before.addProperty("name", name);
                op.before.addProperty("type", s(obj(d, "data"), "type"));
                if (!expectStr(op, "name").equals(name)) {
                    errs.add("expect.name is " + q(op.expect.get("name").getAsString()) + " but the global is named " + q(name) + " now");
                }
                return;
            }
            case "set_global_type": {
                JsonObject d = data(op.address, errs);
                if (d == null) return;
                JsonObject dd = obj(d, "data");
                String type = s(dd, "type") != null ? s(dd, "type") : "undefined";
                JsonElement sz = dd == null ? null : dd.get("size");
                long size = sz != null && sz.isJsonPrimitive() && sz.getAsJsonPrimitive().isNumber() ? sz.getAsLong() : 0;
                op.before = new JsonObject();
                op.before.addProperty("name", s(obj(d, "symbol"), "name"));
                op.before.addProperty("type", type);
                op.before.addProperty("size", size);
                if (!ProposalNorm.normType(type).equals(ProposalNorm.normType(op.expect.get("type").getAsString()))) {
                    errs.add("expect.type is " + q(op.expect.get("type").getAsString()) + " but the global's type is " + q(type) + " now");
                }
                if (size != op.expect.get("size").getAsLong()) {
                    errs.add("expect.size is " + op.expect.get("size").getAsLong() + " but the global's size is " + size + " now");
                }
                return;
            }
            case "rename_local":
            case "retype_local": {
                JsonObject fi = fn(op.function, errs, "function");
                if (fi == null) return;
                String fname = s(fi, "name");
                List<JsonObject> vars = variables(fi);
                List<JsonObject> at = new ArrayList<>();
                Set<String> storages = new LinkedHashSet<>();
                for (JsonObject v : vars) {
                    storages.add(s(v, "storage"));
                    if (s(v, "storage").equals(op.storage)) at.add(v);
                }
                if (at.isEmpty()) {
                    errs.add("no parameter or local of " + fname + " lives at " + op.storage + " (its storages: "
                        + (storages.isEmpty() ? "none" : String.join(", ", storages)) + ")");
                    return;
                }
                JsonObject v = null;
                if (op.kind.equals("rename_local")) {
                    for (JsonObject x : at) if (s(x, "name").equals(expectStr(op, "name"))) { v = x; break; }
                    if (v == null) {
                        List<String> names = new ArrayList<>();
                        for (JsonObject x : at) names.add(q(s(x, "name")));
                        errs.add("expect.name is " + q(op.expect.get("name").getAsString()) + " but at " + op.storage + " " + fname + " has " + String.join(", ", names) + " now");
                        return;
                    }
                } else {
                    String want = ProposalNorm.normType(op.expect.get("type").getAsString());
                    for (JsonObject x : at) {
                        String rt = s(x, "resolvedType");
                        if (ProposalNorm.normType(s(x, "dataType")).equals(want) || (rt != null && ProposalNorm.normType(rt).equals(want))) { v = x; break; }
                    }
                    if (v == null) {
                        List<String> seen = new ArrayList<>();
                        for (JsonObject x : at) {
                            String rt = s(x, "resolvedType");
                            seen.add(s(x, "name") + ": " + q(s(x, "dataType")) + (rt != null ? " (decompiles as " + q(rt) + ")" : ""));
                        }
                        errs.add("expect.type is " + q(op.expect.get("type").getAsString()) + " but at " + op.storage + " " + fname + " has " + String.join(", ", seen) + " now");
                        return;
                    }
                }
                // The existing tools address a variable by name; refuse when that name is not unique.
                int sameName = 0;
                for (JsonObject x : vars) if (s(x, "name").equals(s(v, "name"))) sameName++;
                if (sameName > 1) {
                    errs.add(fname + " has " + sameName + " variables named " + q(s(v, "name")) + "; the one at " + op.storage + " cannot be told apart");
                    return;
                }
                op.varName = s(v, "name");
                op.before = localView(fname, v);
                return;
            }
            case "set_prototype": {
                JsonObject fi = fn(op.address, errs, "address");
                if (fi == null) return;
                op.before = new JsonObject();
                op.before.addProperty("signature", s(fi, "signature"));
                op.before.addProperty("callingConvention", s(fi, "callingConvention"));
                if (!ProposalNorm.normSignature(s(fi, "signature")).equals(ProposalNorm.normSignature(op.expect.get("signature").getAsString()))) {
                    errs.add("expect.signature is " + q(op.expect.get("signature").getAsString()) + " but the signature is " + q(s(fi, "signature")) + " now");
                }
                if (!ProposalNorm.normConvention(s(fi, "callingConvention")).equals(ProposalNorm.normConvention(op.expect.get("callingConvention").getAsString()))) {
                    errs.add("expect.callingConvention is " + q(op.expect.get("callingConvention").getAsString()) + " but it is " + q(s(fi, "callingConvention")) + " now");
                }
                return;
            }
            case "struct_field": {
                JsonObject dt = structView(op, errs);
                if (dt == null) return;
                String kind = s(dt, "type");
                if (!"structure".equals(kind) && !"union".equals(kind)) {
                    errs.add("typePath " + q(op.typePath) + " is a " + (kind != null ? kind : "type") + " with no fields, not a struct");
                    return;
                }
                if ("union".equals(kind)) {
                    errs.add("typePath " + q(op.typePath) + " is a union; update_structure, which applies struct_field, edits structures only");
                    return;
                }
                String hash = ProposalNorm.defHash(dt);
                List<JsonObject> at = new ArrayList<>();
                List<String> starts = new ArrayList<>();
                JsonElement fl = dt.get("fields");
                if (fl != null && fl.isJsonArray()) {
                    for (JsonElement e : fl.getAsJsonArray()) {
                        JsonObject f = e.getAsJsonObject();
                        if (starts.size() < 40) starts.add(String.valueOf(f.get("offset")));
                        if (f.has("offset") && f.get("offset").isJsonPrimitive() && f.get("offset").getAsInt() == op.offset) at.add(f);
                    }
                }
                if (at.isEmpty()) {
                    errs.add(s(dt, "name") + " has no field at offset " + op.offset + " (0x" + Integer.toHexString(op.offset) + "); fields start at " + String.join(", ", starts));
                    return;
                }
                JsonObject f = null;
                for (JsonObject x : at) if (expectStr(op, "name").equals(s(x, "name"))) { f = x; break; }
                JsonObject shown = f != null ? f : at.get(0);
                op.before = new JsonObject();
                op.before.addProperty("struct", s(dt, "name"));
                op.before.addProperty("category", s(dt, "category"));
                op.before.addProperty("name", s(shown, "name"));
                op.before.addProperty("type", s(shown, "dataType"));
                op.before.addProperty("defHash", hash);
                if (f == null) {
                    List<String> names = new ArrayList<>();
                    for (JsonObject x : at) names.add(q(s(x, "name")));
                    errs.add("expect.name is " + q(op.expect.get("name").getAsString()) + " but the field at offset " + op.offset + " is " + String.join(", ", names) + " now");
                    return;
                }
                if (!ProposalNorm.normType(s(f, "dataType")).equals(ProposalNorm.normType(op.expect.get("type").getAsString()))) {
                    errs.add("expect.type is " + q(op.expect.get("type").getAsString()) + " but the field's type is " + q(s(f, "dataType")) + " now");
                }
                if (!expectStr(op, "defHash").equals(hash)) {
                    errs.add("expect.defHash is \"" + expectStr(op, "defHash") + "\" but " + s(dt, "name") + " hashes to \"" + hash + "\" now");
                }
                op.dataType = dt;
                op.field = f;
                return;
            }
            default:
                errs.add("unknown op " + op.kind);
        }
    }

    private static JsonObject localView(String function, JsonObject v) {
        JsonObject o = new JsonObject();
        o.addProperty("function", function);
        o.addProperty("name", s(v, "name"));
        o.addProperty("type", s(v, "dataType"));
        o.add("resolvedType", v.get("resolvedType"));
        o.addProperty("storage", s(v, "storage"));
        return o;
    }

    // ---------------------------------------------------------------- apply (the existing tools' code)

    /** The read-before-write guard is satisfied by the expect check made in this transaction. */
    private void markRead(String address) throws Exception {
        Function func = engine.requireFunction(address, null);
        engine.getContext().recordFunctionRead(func.getEntryPoint().toString(), engine.getProgram().getModificationNumber());
    }

    private void applyOp(Op op) throws Exception {
        switch (op.kind) {
            case "rename_function":
                engine.renameSymbol(op.address, op.name, "function", null);
                return;
            case "rename_global":
                engine.renameSymbol(op.address, op.name, "data", null);
                return;
            case "rename_local":
                markRead(op.function);
                engine.setFunctionVariableName(op.function, op.varName, op.name, null, false);
                return;
            case "retype_local":
                markRead(op.function);
                engine.setFunctionVariableType(op.function, op.varName, op.type, null, true, false);
                return;
            case "set_prototype":
                markRead(op.address);
                // force=false: a function with custom register storage is refused, never silently reset.
                engine.setPrototype(op.address, op.signature, null, op.callingConvention, false);
                return;
            case "set_global_type":
                engine.setDataType(op.address, op.type, -1);
                return;
            case "struct_field": {
                GhidraEngine.StructField update = new GhidraEngine.StructField();
                // Target by offset when only one component starts there, else by its (checked) name.
                int atOffset = 0;
                for (JsonElement e : op.dataType.getAsJsonArray("fields")) {
                    JsonObject f = e.getAsJsonObject();
                    if (f.get("offset").getAsInt() == op.offset) atOffset++;
                }
                if (atOffset == 1) update.offset = op.offset;
                else update.fieldName = s(op.field, "name");
                update.newName = op.name;
                update.newDataType = op.type;
                List<GhidraEngine.StructField> fields = new ArrayList<>();
                fields.add(update);
                engine.updateStructure(s(op.dataType, "name"), s(op.dataType, "category"), "updateFields", fields, null, false);
                return;
            }
            default:
                throw new Exception("unknown op " + op.kind);
        }
    }

    /** The op's target as it reads now, in the same shape as `before`. */
    private JsonObject view(Op op) throws Exception {
        List<String> errs = new ArrayList<>();
        switch (op.kind) {
            case "rename_function": {
                JsonObject fi = read("get_function_info", args("address", op.address));
                JsonObject o = new JsonObject();
                o.addProperty("name", s(fi, "name"));
                o.add("namespace", fi.has("namespace") ? fi.get("namespace") : JsonNull.INSTANCE);
                return o;
            }
            case "rename_global":
            case "set_global_type": {
                JsonObject d = read("get_data_at_address", args("address", op.address));
                JsonObject dd = obj(d, "data");
                JsonObject o = new JsonObject();
                o.addProperty("name", s(obj(d, "symbol"), "name"));
                o.addProperty("type", s(dd, "type"));
                if (op.kind.equals("set_global_type")) {
                    JsonElement sz = dd == null ? null : dd.get("size");
                    o.addProperty("size", sz != null && sz.isJsonPrimitive() && sz.getAsJsonPrimitive().isNumber() ? sz.getAsLong() : 0);
                }
                return o;
            }
            case "rename_local":
            case "retype_local": {
                JsonObject fi = read("get_function_info", args("address", op.function));
                for (JsonObject v : variables(fi)) {
                    if (s(v, "storage").equals(op.storage)
                            && (op.kind.equals("retype_local") ? s(v, "name").equals(op.varName) : s(v, "name").equals(op.name))) {
                        return localView(s(fi, "name"), v);
                    }
                }
                for (JsonObject v : variables(fi)) {
                    if (s(v, "storage").equals(op.storage)) return localView(s(fi, "name"), v);
                }
                JsonObject o = new JsonObject();
                o.addProperty("function", s(fi, "name"));
                o.addProperty("storage", op.storage);
                return o;
            }
            case "set_prototype": {
                JsonObject fi = read("get_function_info", args("address", op.address));
                JsonObject o = new JsonObject();
                o.addProperty("signature", s(fi, "signature"));
                o.addProperty("callingConvention", s(fi, "callingConvention"));
                return o;
            }
            case "struct_field": {
                JsonObject dt = structView(op, errs);
                JsonObject o = new JsonObject();
                if (dt == null) return o;
                o.addProperty("struct", s(dt, "name"));
                o.addProperty("category", s(dt, "category"));
                String want = op.name != null ? op.name : s(op.field, "name");
                for (JsonElement e : dt.getAsJsonArray("fields")) {
                    JsonObject f = e.getAsJsonObject();
                    if (f.get("offset").getAsInt() == op.offset && want.equals(s(f, "name"))) {
                        o.addProperty("name", s(f, "name"));
                        o.addProperty("type", s(f, "dataType"));
                        break;
                    }
                }
                o.addProperty("defHash", ProposalNorm.defHash(dt));
                return o;
            }
            default:
                return new JsonObject();
        }
    }

    // ---------------------------------------------------------------- results

    private static JsonObject opError(int index, String kind, List<String> errs) {
        JsonObject e = new JsonObject();
        e.addProperty("index", index);
        e.addProperty("op", kind == null ? "(missing)" : kind);
        JsonArray a = new JsonArray();
        for (String s : errs) a.add(s);
        e.add("errors", a);
        return e;
    }

    private static String message(Exception e) {
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }
}
