package com.ghidramcp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The Redivivus proposal checker's normalisers and struct fingerprint, in Java.
 *
 * A proposal is checked by redivivus-app (src/proposals/check.ts, schema.ts) and applied here by
 * apply_changeset; a value that passed the check must compare equal here, so these are ports of
 * those functions, not reinterpretations. packages/shared/src/changeset.ts holds the TypeScript
 * copy, and packages/shared/test/changeset-vectors.json - produced by running the checker's own
 * code - holds all three to the same answers (ProposalNormTest here, changeset.test.ts there).
 *
 * defHash: sha256 over stableStringify({name, category, size, fields: [[offset, name, dataType,
 * size, bitOffset, bitSize], ...]}) of the get_data_type result, first 16 lowercase hex digits.
 * stableStringify is JSON with object keys sorted by UTF-16 code unit and no whitespace, strings
 * escaped the way JavaScript's JSON.stringify escapes them.
 */
public final class ProposalNorm {
    private ProposalNorm() {}

    public static final Pattern ADDRESS = Pattern.compile("^(0x)?[0-9a-fA-F]{1,16}$");
    public static final Pattern IDENT = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*$");
    public static final Pattern TYPE = Pattern.compile("^[A-Za-z_][A-Za-z0-9_ *\\[\\]:]*$");
    public static final Pattern CALLING_CONVENTION = Pattern.compile("^(__[a-z][a-z0-9_]*|unknown)$");
    public static final Pattern SIGNATURE = Pattern.compile("^[^()]*\\(.*\\)\\s*$", Pattern.DOTALL);
    public static final Pattern STORAGE =
        Pattern.compile("^(Stack\\[-?0x[0-9a-fA-F]+\\]|[A-Za-z][A-Za-z0-9]{1,5}|HASH:[0-9a-fA-F]+)(:\\d+)?$");
    public static final Pattern TYPE_PATH = Pattern.compile("^(/[A-Za-z0-9_ .+-]+)*/?[A-Za-z_][A-Za-z0-9_]*$");
    public static final Pattern DEF_HASH = Pattern.compile("^[0-9a-f]{16}$");

    private static final Pattern STACK = Pattern.compile("^stack\\[(-?)0x([0-9a-f]+)\\]$", Pattern.CASE_INSENSITIVE);
    /** JavaScript's \s: Java's own \s is ASCII-only, and (?U) would add U+0085 and drop U+FEFF. */
    private static final String WS = "[\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]";
    private static final Pattern HEX = Pattern.compile("^[0-9a-fA-F]+$");

    /** JavaScript's String.prototype.trim: strips whitespace and line terminators. */
    public static String jsTrim(String s) {
        int a = 0, b = s.length();
        while (a < b && isJsSpace(s.charAt(a))) a++;
        while (b > a && isJsSpace(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    private static boolean isJsSpace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0x0B || c == '\f' || c == 0xA0
            || c == 0x1680 || (c >= 0x2000 && c <= 0x200A) || c == 0x2028 || c == 0x2029
            || c == 0x202F || c == 0x205F || c == 0x3000 || c == 0xFEFF;
    }

    /** "0x00401000", "00401000" or "0x401000" become "0x00401000". */
    public static String normAddress(String s) {
        String hex = jsTrim(s).replaceFirst("^(?i)0x", "").replaceFirst("^0+(?=.)", "").toLowerCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder("0x");
        for (int i = hex.length(); i < 8; i++) sb.append('0');
        return sb.append(hex).toString();
    }

    /** Storage as get_function_info prints it, without the ":4" size. */
    public static String normStorage(String s) {
        String bare = jsTrim(s).replaceFirst(":\\d+$", "");
        Matcher m = STACK.matcher(bare);
        if (m.matches()) {
            return "Stack[" + m.group(1) + "0x" + m.group(2).replaceFirst("^0+(?=.)", "").toLowerCase(Locale.ROOT) + "]";
        }
        if (bare.regionMatches(true, 0, "hash:", 0, 5)) return "HASH:" + bare.substring(5).toLowerCase(Locale.ROOT);
        return bare.toUpperCase(Locale.ROOT);
    }

    public static boolean addrEq(String a, String b) {
        if (a == null || b == null) return false;
        String ha = jsTrim(a).replaceFirst("^(?i)0x", "");
        String hb = jsTrim(b).replaceFirst("^(?i)0x", "");
        if (!HEX.matcher(ha).matches() || !HEX.matcher(hb).matches()) return false;
        return new BigInteger(ha, 16).equals(new BigInteger(hb, 16));
    }

    public static String normType(String s) {
        String t = jsTrim(s == null ? "" : s);
        t = t.replaceAll(WS + "+", " ");
        t = t.replaceAll(WS + "*\\*" + WS + "*", "*");
        t = t.replaceAll(WS + "*\\[" + WS + "*", "[");
        t = t.replaceAll(WS + "*\\]", "]");
        return t;
    }

    public static String normSignature(String s) {
        return normType(s).replaceAll(WS + "*([(),])" + WS + "*", "$1");
    }

    public static String normConvention(String s) {
        return jsTrim(s == null ? "" : s).toLowerCase(Locale.ROOT).replaceFirst("^_+", "");
    }

    // ---- defHash ----

    /** The struct fingerprint from a get_data_type result. */
    public static String defHash(JsonObject dt) {
        JsonArray fields = new JsonArray();
        JsonElement list = dt == null ? null : dt.get("fields");
        if (list != null && list.isJsonArray()) {
            for (JsonElement el : list.getAsJsonArray()) {
                JsonObject f = el.isJsonObject() ? el.getAsJsonObject() : new JsonObject();
                JsonArray row = new JsonArray();
                for (String k : new String[] {"offset", "name", "dataType", "size", "bitOffset", "bitSize"}) {
                    row.add(orNull(f.get(k)));
                }
                fields.add(row);
            }
        }
        JsonObject canon = new JsonObject();
        canon.add("name", dt == null ? JsonNull.INSTANCE : orNull(dt.get("name")));
        canon.add("category", dt == null ? JsonNull.INSTANCE : orNull(dt.get("category")));
        canon.add("size", dt == null ? JsonNull.INSTANCE : orNull(dt.get("size")));
        canon.add("fields", fields);
        return sha256Hex(stableStringify(canon)).substring(0, 16);
    }

    private static JsonElement orNull(JsonElement e) {
        return e == null ? JsonNull.INSTANCE : e;
    }

    public static String sha256Hex(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** JSON with object keys sorted (UTF-16 code unit order) and no whitespace. */
    public static String stableStringify(JsonElement v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v);
        return sb.toString();
    }

    private static void write(StringBuilder sb, JsonElement v) {
        if (v == null || v.isJsonNull()) { sb.append("null"); return; }
        if (v.isJsonArray()) {
            sb.append('[');
            boolean first = true;
            for (JsonElement e : v.getAsJsonArray()) {
                if (!first) sb.append(',');
                first = false;
                write(sb, e);
            }
            sb.append(']');
            return;
        }
        if (v.isJsonObject()) {
            List<String> keys = new ArrayList<>(v.getAsJsonObject().keySet());
            keys.sort(String::compareTo);
            sb.append('{');
            boolean first = true;
            for (String k : keys) {
                if (!first) sb.append(',');
                first = false;
                quote(sb, k);
                sb.append(':');
                write(sb, v.getAsJsonObject().get(k));
            }
            sb.append('}');
            return;
        }
        JsonPrimitive p = v.getAsJsonPrimitive();
        if (p.isBoolean()) sb.append(p.getAsBoolean());
        else if (p.isNumber()) sb.append(jsNumber(p.getAsNumber()));
        else quote(sb, p.getAsString());
    }

    /** A number as JSON.stringify writes it, for the integers and plain decimals Ghidra reports. */
    static String jsNumber(Number n) {
        BigDecimal d = new BigDecimal(n.toString());
        if (d.signum() == 0) return "0";
        BigDecimal stripped = d.stripTrailingZeros();
        if (stripped.scale() <= 0 && stripped.abs().compareTo(new BigDecimal("1e21")) < 0) {
            return stripped.toBigInteger().toString();
        }
        double x = d.doubleValue();
        if (Double.isNaN(x) || Double.isInfinite(x)) return "null";
        // Non-integers: shortest round-trip form, which is what both runtimes produce for
        // ordinary magnitudes.
        String s = Double.toString(x);
        if (s.contains("E")) {
            String[] parts = s.split("E");
            String mant = parts[0].endsWith(".0") ? parts[0].substring(0, parts[0].length() - 2) : parts[0];
            int exp = Integer.parseInt(parts[1]);
            return mant + "e" + (exp >= 0 ? "+" : "") + exp;
        }
        return s.endsWith(".0") ? s.substring(0, s.length() - 2) : s;
    }

    /** A string as JSON.stringify quotes it. */
    static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else if (Character.isHighSurrogate(c)) {
                        if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                            sb.append(c).append(s.charAt(++i));
                        } else {
                            sb.append(String.format("\\u%04x", (int) c));
                        }
                    } else if (Character.isLowSurrogate(c)) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }
}
