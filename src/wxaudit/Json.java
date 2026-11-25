package wxaudit;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal zero-dependency JSON parser/serializer (Java 8 compatible).
 * 极简零依赖 JSON 解析器 / Minimal dependency-free JSON parser.
 *
 * 用途：解析 OpenAI 兼容端点的响应，序列化 AI 配置 / Used to parse OpenAI-compatible
 * responses and serialize AI configuration.
 */
public final class Json {

    /** JSON 解析异常 / JSON parse exception. */
    public static final class JsonException extends Exception {
        private static final long serialVersionUID = 1L;
        public JsonException(String message) { super(message); }
    }

    private Json() { }

    /** 解析 JSON 文本，返回 Map/List/String/Long/Double/Boolean/null。 */
    public static Object parse(String text) throws JsonException {
        if (text == null) throw new JsonException("null input");
        Parser p = new Parser(text);
        p.skipWs();
        Object value = p.value();
        p.skipWs();
        if (p.pos < text.length()) throw new JsonException("trailing data at " + p.pos);
        return value;
    }

    /** 解析并强制为 JSON 对象。 */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) throws JsonException {
        Object v = parse(text);
        if (!(v instanceof Map)) throw new JsonException("not a JSON object");
        return (Map<String, Object>) v;
    }

    /** 把字符串编码为带引号的 JSON 字符串（含转义）。 */
    public static String quote(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder(s.length() + 2);
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        String hex = Integer.toHexString((int) c);
                        while (hex.length() < 4) hex = "0" + hex;
                        b.append("\\u").append(hex);
                    } else {
                        b.append(c);
                    }
            }
        }
        b.append('"');
        return b.toString();
    }

    /** 序列化 Map/List/标量 为 JSON 字符串。 */
    public static String stringify(Object o) {
        StringBuilder b = new StringBuilder();
        write(o, b);
        return b.toString();
    }

    private static void write(Object o, StringBuilder b) {
        if (o == null) { b.append("null"); return; }
        if (o instanceof String) { b.append(quote((String) o)); return; }
        if (o instanceof Boolean || o instanceof Number) { b.append(o.toString()); return; }
        if (o instanceof Map) {
            b.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) {
                if (!first) b.append(',');
                first = false;
                b.append(quote(String.valueOf(e.getKey()))).append(':');
                write(e.getValue(), b);
            }
            b.append('}');
            return;
        }
        if (o instanceof List) {
            b.append('[');
            boolean first = true;
            for (Object item : (List<?>) o) {
                if (!first) b.append(',');
                first = false;
                write(item, b);
            }
            b.append(']');
            return;
        }
        b.append(quote(o.toString()));
    }

    /** 剥离模型常见的 markdown 代码围栏（```json ... ```）。 */
    public static String stripFence(String s) {
        if (s == null) return "";
        String t = s.trim();
        if (t.startsWith("```")) {
            int nl = t.indexOf('\n');
            if (nl > 0) t = t.substring(nl + 1);
            int end = t.lastIndexOf("```");
            if (end >= 0) t = t.substring(0, end);
        }
        return t.trim();
    }

    // ------------------------------------------------------------------
    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObject(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asList(Object o) {
        return o instanceof List ? (List<Object>) o : null;
    }

    public static String asString(Object o) {
        return o instanceof String ? (String) o : null;
    }

    public static int asInt(Object o, int def) {
        if (o instanceof Number) return ((Number) o).intValue();
        return def;
    }

    public static boolean asBool(Object o, boolean def) {
        if (o instanceof Boolean) return ((Boolean) o).booleanValue();
        return def;
    }

    // ------------------------------------------------------------------
    private static final class Parser {
        private final String s;
        private int pos = 0;

        Parser(String s) { this.s = s; }

        void skipWs() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        Object value() throws JsonException {
            skipWs();
            if (pos >= s.length()) throw new JsonException("unexpected end");
            char c = s.charAt(pos);
            if (c == '{') return object();
            if (c == '[') return array();
            if (c == '"') return string();
            if (c == 't') return literal("true", Boolean.TRUE);
            if (c == 'f') return literal("false", Boolean.FALSE);
            if (c == 'n') return literal("null", null);
            if (c == '-' || (c >= '0' && c <= '9')) return number();
            throw new JsonException("unexpected char '" + c + "' at " + pos);
        }

        private Object literal(String lit, Object v) throws JsonException {
            if (!s.startsWith(lit, pos)) throw new JsonException("invalid literal at " + pos);
            pos += lit.length();
            return v;
        }

        private Map<String, Object> object() throws JsonException {
            pos++; // consume '{'
            Map<String, Object> m = new LinkedHashMap<String, Object>();
            skipWs();
            if (pos < s.length() && s.charAt(pos) == '}') { pos++; return m; }
            while (true) {
                skipWs();
                if (pos >= s.length() || s.charAt(pos) != '"') throw new JsonException("expected key at " + pos);
                String key = string();
                skipWs();
                if (pos >= s.length() || s.charAt(pos) != ':') throw new JsonException("expected ':' at " + pos);
                pos++;
                Object val = value();
                m.put(key, val);
                skipWs();
                if (pos >= s.length()) throw new JsonException("unterminated object");
                char c = s.charAt(pos++);
                if (c == '}') break;
                if (c != ',') throw new JsonException("expected ',' or '}' at " + (pos - 1));
            }
            return m;
        }

        private List<Object> array() throws JsonException {
            pos++; // consume '['
            List<Object> a = new ArrayList<Object>();
            skipWs();
            if (pos < s.length() && s.charAt(pos) == ']') { pos++; return a; }
            while (true) {
                a.add(value());
                skipWs();
                if (pos >= s.length()) throw new JsonException("unterminated array");
                char c = s.charAt(pos++);
                if (c == ']') break;
                if (c != ',') throw new JsonException("expected ',' or ']' at " + (pos - 1));
            }
            return a;
        }

        private String string() throws JsonException {
            pos++; // consume '"'
            StringBuilder b = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == '"') return b.toString();
                if (c == '\\') {
                    if (pos >= s.length()) throw new JsonException("unterminated escape");
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': b.append('"'); break;
                        case '\\': b.append('\\'); break;
                        case '/': b.append('/'); break;
                        case 'b': b.append('\b'); break;
                        case 'f': b.append('\f'); break;
                        case 'n': b.append('\n'); break;
                        case 'r': b.append('\r'); break;
                        case 't': b.append('\t'); break;
                        case 'u':
                            if (pos + 4 > s.length()) throw new JsonException("bad unicode escape");
                            String hex = s.substring(pos, pos + 4);
                            int cp;
                            try { cp = Integer.parseInt(hex, 16); }
                            catch (NumberFormatException ex) { throw new JsonException("bad unicode escape"); }
                            b.append((char) cp);
                            pos += 4;
                            break;
                        default: throw new JsonException("bad escape at " + (pos - 1));
                    }
                } else if (c < 0x20) {
                    throw new JsonException("control character in string");
                } else {
                    b.append(c);
                }
            }
            throw new JsonException("unterminated string");
        }

        private Number number() throws JsonException {
            int start = pos;
            if (s.charAt(pos) == '-') pos++;
            int digits = 0;
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) { pos++; digits++; }
            if (digits == 0) throw new JsonException("bad number at " + start);
            boolean isDouble = false;
            if (pos < s.length() && s.charAt(pos) == '.') {
                isDouble = true; pos++;
                int frac = 0;
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) { pos++; frac++; }
                if (frac == 0) throw new JsonException("bad fraction at " + start);
            }
            if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                isDouble = true; pos++;
                if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++;
                int exp = 0;
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) { pos++; exp++; }
                if (exp == 0) throw new JsonException("bad exponent at " + start);
            }
            String num = s.substring(start, pos);
            try {
                return isDouble ? Double.valueOf(num) : Long.valueOf(num);
            } catch (NumberFormatException ex) {
                throw new JsonException("bad number: " + num);
            }
        }
    }
}
