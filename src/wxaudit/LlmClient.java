package wxaudit;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Map;

/**
 * OpenAI 兼容端点 HTTP 客户端（零依赖，Java 8）/ OpenAI-compatible HTTP client.
 *
 * <p>只用 {@code java.net.HttpURLConnection}，禁用 Java 11+ 的 HttpClient，
 * 保持 JDK8 编译与可复现构建。构造不联网，仅在 chat() 时发起请求。
 */
public final class LlmClient {
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_RESPONSE = 1024 * 1024; // 1MB

    private final String endpoint;
    private final String apiKey;
    private final String model;
    private final int timeoutMs;
    private final int maxTokens;
    private final double temperature;
    private final boolean enabled;

    /** 传输层异常 / Transport exception. */
    public static final class LlmException extends Exception {
        private static final long serialVersionUID = 1L;
        public enum Kind { DISABLED, HTTP, TIMEOUT, IO, PARSE }
        public final Kind kind;
        public final int statusCode;
        public LlmException(Kind kind, String message) { this(kind, 0, message); }
        public LlmException(Kind kind, int statusCode, String message) {
            super(message);
            this.kind = kind;
            this.statusCode = statusCode;
        }
    }

    public LlmClient(AiConfig cfg) {
        this.enabled = cfg.isNetworkAllowed();
        this.endpoint = normalizeEndpoint(cfg.baseUrl);
        this.apiKey = cfg.apiKey;
        this.model = cfg.model;
        this.timeoutMs = cfg.timeoutMs;
        this.maxTokens = cfg.maxTokens;
        this.temperature = cfg.temperature;
    }

    /** 端点归一化：去尾斜杠，补全 /chat/completions。 */
    static String normalizeEndpoint(String base) {
        if (base == null) return "";
        String b = base.trim();
        while (b.endsWith("/")) b = b.substring(0, b.length() - 1);
        if (b.isEmpty()) return "";
        if (b.endsWith("/chat/completions")) return b;
        // 兼容用户填 /v1 或 /v1/chat/completions 之外的路径
        return b + "/chat/completions";
    }

    /** 发起 chat 请求，返回原始响应文本（调用方负责解析）。 */
    public String chat(String systemPrompt, String userPrompt) throws LlmException {
        if (!enabled) throw new LlmException(LlmException.Kind.DISABLED, "AI disabled or not configured");
        if (endpoint.isEmpty()) throw new LlmException(LlmException.Kind.DISABLED, "empty endpoint");

        StringBuilder body = new StringBuilder(1024);
        body.append('{');
        body.append("\"model\":").append(Json.quote(model)).append(',');
        body.append("\"messages\":[");
        body.append("{\"role\":\"system\",\"content\":").append(Json.quote(systemPrompt)).append("},");
        body.append("{\"role\":\"user\",\"content\":").append(Json.quote(userPrompt)).append("}");
        body.append("],");
        body.append("\"temperature\":").append(temperature).append(',');
        body.append("\"max_tokens\":").append(maxTokens).append(',');
        body.append("\"stream\":false");
        body.append('}');
        byte[] payload = body.toString().getBytes(UTF8);

        HttpURLConnection conn = null;
        try {
            URL url = new URL(endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            conn.setRequestProperty("User-Agent", "wxaudit-burp/1.1");
            conn.setFixedLengthStreamingMode(payload.length);

            OutputStream os = conn.getOutputStream();
            try { os.write(payload); os.flush(); }
            finally { os.close(); }

            int status = conn.getResponseCode();
            InputStream is = status >= 200 && status < 300
                    ? conn.getInputStream() : conn.getErrorStream();
            String text = readLimited(is, MAX_RESPONSE);
            if (status < 200 || status >= 300) {
                throw new LlmException(LlmException.Kind.HTTP, status,
                        "HTTP " + status + ": " + brief(text));
            }
            return text;
        } catch (LlmException le) {
            throw le;
        } catch (java.net.SocketTimeoutException te) {
            throw new LlmException(LlmException.Kind.TIMEOUT, "request timed out after " + timeoutMs + "ms");
        } catch (java.net.SocketException se) {
            throw new LlmException(LlmException.Kind.IO, "socket error: " + brief(se.getMessage()));
        } catch (java.io.IOException ioe) {
            throw new LlmException(LlmException.Kind.IO, "I/O error: " + brief(ioe.getMessage()));
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** 从 OpenAI 响应中提取 choices[0].message.content。 */
    public static String extractContent(String responseJson) throws LlmException {
        try {
            Map<String, Object> root = Json.parseObject(Json.stripFence(responseJson));
            java.util.List<Object> choices = Json.asList(root.get("choices"));
            if (choices == null || choices.isEmpty())
                throw new LlmException(LlmException.Kind.PARSE, "no choices in response");
            Map<String, Object> first = Json.asObject(choices.get(0));
            if (first == null) throw new LlmException(LlmException.Kind.PARSE, "bad choice");
            Map<String, Object> message = Json.asObject(first.get("message"));
            if (message == null) throw new LlmException(LlmException.Kind.PARSE, "bad message");
            String content = Json.asString(message.get("content"));
            if (content == null) throw new LlmException(LlmException.Kind.PARSE, "null content");
            return content;
        } catch (Json.JsonException je) {
            throw new LlmException(LlmException.Kind.PARSE, "invalid JSON: " + brief(je.getMessage()));
        }
    }

    private static String readLimited(InputStream is, int limit) throws java.io.IOException {
        if (is == null) return "";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n, total = 0;
        try {
            while ((n = is.read(buf)) != -1) {
                if (total + n > limit) n = limit - total;
                if (n <= 0) break;
                bos.write(buf, 0, n);
                total += n;
                if (total >= limit) break;
            }
        } finally {
            try { is.close(); } catch (java.io.IOException ignore) { }
        }
        return new String(bos.toByteArray(), UTF8);
    }

    private static String brief(String s) {
        if (s == null) return "";
        String t = s.trim().replace('\r', ' ').replace('\n', ' ');
        return t.length() > 300 ? t.substring(0, 300) : t;
    }
}
