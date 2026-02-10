package com.gqlasa.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Lightweight JSON utilities.
 *
 * This project previously relied on Jackson, but Burp's runtime classloader can
 * cause NoClassDefFoundError / linkage issues when external JSON libraries are
 * shaded/relocated. To keep the extension robust, this class provides a small
 * parser and pretty-printer with no external dependencies.
 */
public final class Json {
    private Json() {}

    /**
     * Backwards-compatible field (older code referenced Json.MAPPER).
     * Kept only for source compatibility; always null.
     */
    public static final Object MAPPER = null;

    public static String compact(Object obj) {
        return write(obj, false);
    }

    public static String toCompactString(Object obj) {
        return compact(obj);
    }

    public static String toPrettyString(Object obj) {
        return write(obj, true);
    }

    public static String pretty(Map<String, Object> map) {
        return write(map, true);
    }

    public static String stringify(Map<String, Object> map) {
        return write(map, false);
    }

    public static String stringify(List<Map<String, Object>> list) {
        return write(list, false);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseMap(String json) {
        Object o = parse(json);
        if (o instanceof Map) return (Map<String, Object>) o;
        return Map.of();
    }

    /** Parse arbitrary JSON into Map/List/scalars. */
    public static Object parse(String json) {
        try {
            return MiniJson.parse(json);
        } catch (Throwable t) {
            return null;
        }
    }

    // ---------------------------- Writer ----------------------------

    private static String write(Object obj, boolean pretty) {
        StringBuilder sb = new StringBuilder(256);
        writeValue(sb, obj, pretty, 0);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeValue(StringBuilder sb, Object v, boolean pretty, int indent) {
        if (v == null) { sb.append("null"); return; }

        // Special-case BurpBody (and other simple POJOs) so we emit a JSON object,
        // not a Java toString(). This fixes bodies like "com.gqlasa.model.BurpBody@..."
        // being sent to Repeater.
        if ("com.gqlasa.model.BurpBody".equals(v.getClass().getName())) {
            try {
                var cls = v.getClass();
                Object q = cls.getField("query").get(v);
                Object op = cls.getField("operationName").get(v);
                Object vars = cls.getField("variables").get(v);
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("query", q);
                if (op != null && !String.valueOf(op).isBlank()) m.put("operationName", op);
                m.put("variables", (vars instanceof Map) ? vars : Map.of());
                writeValue(sb, m, pretty, indent);
                return;
            } catch (Throwable ignored) {
                // fall through
            }
        }
        if (v instanceof String) { sb.append('"').append(escape((String) v)).append('"'); return; }
        if (v instanceof Number || v instanceof Boolean) { sb.append(String.valueOf(v)); return; }

        if (v instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) v;
            sb.append('{');
            if (!m.isEmpty()) {
                boolean first = true;
                for (Map.Entry<String, Object> e : m.entrySet()) {
                    if (!first) sb.append(',');
                    first = false;
                    if (pretty) { sb.append('\n'); indent(sb, indent + 2); }
                    sb.append('"').append(escape(String.valueOf(e.getKey()))).append('"').append(':');
                    if (pretty) sb.append(' ');
                    writeValue(sb, e.getValue(), pretty, indent + 2);
                }
                if (pretty) { sb.append('\n'); indent(sb, indent); }
            }
            sb.append('}');
            return;
        }

        if (v instanceof List) {
            List<Object> a = (List<Object>) v;
            sb.append('[');
            if (!a.isEmpty()) {
                boolean first = true;
                for (Object item : a) {
                    if (!first) sb.append(',');
                    first = false;
                    if (pretty) { sb.append('\n'); indent(sb, indent + 2); }
                    writeValue(sb, item, pretty, indent + 2);
                }
                if (pretty) { sb.append('\n'); indent(sb, indent); }
            }
            sb.append(']');
            return;
        }

        // Fallback
        sb.append('"').append(escape(String.valueOf(v))).append('"');
    }

    private static void indent(StringBuilder sb, int n) {
        for (int i = 0; i < n; i++) sb.append(' ');
    }

    private static String escape(String s) {
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    // ---------------------------- Parser ----------------------------

    private static final class MiniJson {
        private final String s;
        private int i;

        private MiniJson(String s) { this.s = s; }

        static Object parse(String s) {
            if (s == null) return null;
            MiniJson p = new MiniJson(s);
            p.skipWs();
            Object v = p.readValue();
            p.skipWs();
            return v;
        }

        private void skipWs() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\n' || c == '\r' || c == '\t') i++;
                else break;
            }
        }

        private Object readValue() {
            skipWs();
            if (i >= s.length()) return null;
            char c = s.charAt(i);
            if (c == '{') return readObject();
            if (c == '[') return readArray();
            if (c == '"') return readString();
            if (c == 't' && s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            if (c == 'f' && s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (c == 'n' && s.startsWith("null", i)) { i += 4; return null; }
            return readNumber();
        }

        private Map<String, Object> readObject() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++; // {
            skipWs();
            if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
            while (i < s.length()) {
                skipWs();
                String key = readString();
                skipWs();
                if (i < s.length() && s.charAt(i) == ':') i++; else break;
                Object val = readValue();
                m.put(key, val);
                skipWs();
                if (i < s.length() && s.charAt(i) == ',') { i++; continue; }
                if (i < s.length() && s.charAt(i) == '}') { i++; break; }
            }
            return m;
        }

        private List<Object> readArray() {
            List<Object> a = new ArrayList<>();
            i++; // [
            skipWs();
            if (i < s.length() && s.charAt(i) == ']') { i++; return a; }
            while (i < s.length()) {
                Object v = readValue();
                a.add(v);
                skipWs();
                if (i < s.length() && s.charAt(i) == ',') { i++; continue; }
                if (i < s.length() && s.charAt(i) == ']') { i++; break; }
            }
            return a;
        }

        private String readString() {
            if (i >= s.length() || s.charAt(i) != '"') return "";
            i++; // opening quote
            StringBuilder out = new StringBuilder();
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') break;
                if (c == '\\' && i < s.length()) {
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"': out.append('"'); break;
                        case '\\': out.append('\\'); break;
                        case '/': out.append('/'); break;
                        case 'b': out.append('\b'); break;
                        case 'f': out.append('\f'); break;
                        case 'n': out.append('\n'); break;
                        case 'r': out.append('\r'); break;
                        case 't': out.append('\t'); break;
                        case 'u':
                            if (i + 3 < s.length()) {
                                String hex = s.substring(i, i + 4);
                                try { out.append((char) Integer.parseInt(hex, 16)); } catch (Exception ignored) {}
                                i += 4;
                            }
                            break;
                        default:
                            out.append(e);
                    }
                } else {
                    out.append(c);
                }
            }
            return out.toString();
        }

        private Number readNumber() {
            int start = i;
            boolean dot = false;
            boolean exp = false;
            if (i < s.length() && (s.charAt(i) == '-' || s.charAt(i) == '+')) i++;
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c >= '0' && c <= '9') { i++; continue; }
                if (c == '.' && !dot) { dot = true; i++; continue; }
                if ((c == 'e' || c == 'E') && !exp) { exp = true; i++; if (i < s.length() && (s.charAt(i) == '-' || s.charAt(i) == '+')) i++; continue; }
                break;
            }
            String num = s.substring(start, i);
            try {
                if (dot || exp) return Double.parseDouble(num);
                long l = Long.parseLong(num);
                if (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) return (int) l;
                return l;
            } catch (Exception e) {
                return 0;
            }
        }
    }
}
