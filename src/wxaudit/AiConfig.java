package wxaudit;

import java.util.Map;

/**
 * AI 配置值对象 / AI configuration value object.
 *
 * <p>默认 enabled=false，不配置 Key 时零外发。存储于 Burp 扩展设置（单个 JSON key），
 * 不落盘到独立文件。/ Defaults to disabled; no network calls without a configured key.
 * Persisted in Burp extension settings as a single JSON key, never to a standalone file.
 */
public final class AiConfig {

    public final boolean enabled;
    public final String baseUrl;
    public final String apiKey;
    public final String model;
    public final int timeoutMs;
    public final int maxBatch;
    public final int maxTokens;
    public final boolean realtime;
    public final boolean exploitChain;
    public final double temperature;

    public AiConfig(boolean enabled, String baseUrl, String apiKey, String model,
                    int timeoutMs, int maxBatch, int maxTokens,
                    boolean realtime, boolean exploitChain, double temperature) {
        this.enabled = enabled;
        this.baseUrl = baseUrl == null ? "" : baseUrl.trim();
        this.apiKey = apiKey == null ? "" : apiKey.trim();
        this.model = model == null ? "" : model.trim();
        this.timeoutMs = timeoutMs <= 0 ? 30000 : timeoutMs;
        this.maxBatch = maxBatch <= 0 ? 10 : maxBatch;
        this.maxTokens = maxTokens <= 0 ? 2000 : maxTokens;
        this.realtime = realtime;
        this.exploitChain = exploitChain;
        this.temperature = temperature;
    }

    /** 全默认：禁用、无任何外发能力。 */
    public static AiConfig defaults() {
        return new AiConfig(false, "", "", "", 30000, 10, 2000, false, true, 0);
    }

    /**
     * 是否允许发起网络请求（双闸门之一）。必须显式启用且 baseUrl/apiKey/model 均非空。
     */
    public boolean isNetworkAllowed() {
        return enabled && !baseUrl.isEmpty() && !apiKey.isEmpty() && !model.isEmpty();
    }

    /** 校验配置，返回中文错误串；返回 null 表示合法。 */
    public String validate() {
        if (!enabled) return null;
        if (baseUrl.isEmpty()) return "API 地址不能为空 / baseUrl required";
        if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://"))
            return "API 地址须以 http:// 或 https:// 开头";
        if (apiKey.isEmpty()) return "API Key 不能为空 / API key required";
        if (model.isEmpty()) return "模型名不能为空 / model required";
        if (timeoutMs < 1000 || timeoutMs > 300000) return "超时需在 1000~300000 毫秒之间";
        if (maxBatch < 1 || maxBatch > 50) return "每批上限需在 1~50 之间";
        if (maxTokens < 100 || maxTokens > 32000) return "max_tokens 需在 100~32000 之间";
        return null;
    }

    /** 序列化，包含版本字段 v 便于演进。 */
    public String toJson() {
        StringBuilder b = new StringBuilder(256);
        b.append('{');
        b.append("\"v\":1,");
        b.append("\"enabled\":").append(enabled).append(',');
        b.append("\"baseUrl\":").append(Json.quote(baseUrl)).append(',');
        b.append("\"apiKey\":").append(Json.quote(apiKey)).append(',');
        b.append("\"model\":").append(Json.quote(model)).append(',');
        b.append("\"timeoutMs\":").append(timeoutMs).append(',');
        b.append("\"maxBatch\":").append(maxBatch).append(',');
        b.append("\"maxTokens\":").append(maxTokens).append(',');
        b.append("\"realtime\":").append(realtime).append(',');
        b.append("\"exploitChain\":").append(exploitChain).append(',');
        b.append("\"temperature\":").append(temperature);
        b.append('}');
        return b.toString();
    }

    /** 反序列化；任何异常回退到默认禁用配置，保证安全。 */
    public static AiConfig fromJson(String s) {
        if (s == null || s.trim().isEmpty()) return defaults();
        try {
            Map<String, Object> m = Json.parseObject(s);
            return new AiConfig(
                    Json.asBool(m.get("enabled"), false),
                    str(m.get("baseUrl")),
                    str(m.get("apiKey")),
                    str(m.get("model")),
                    Json.asInt(m.get("timeoutMs"), 30000),
                    Json.asInt(m.get("maxBatch"), 10),
                    Json.asInt(m.get("maxTokens"), 2000),
                    Json.asBool(m.get("realtime"), false),
                    Json.asBool(m.get("exploitChain"), true),
                    dbl(m.get("temperature"), 0)
            );
        } catch (Exception ex) {
            return defaults();
        }
    }

    private static String str(Object o) {
        return o instanceof String ? (String) o : "";
    }

    private static double dbl(Object o, double def) {
        if (o instanceof Number) return ((Number) o).doubleValue();
        return def;
    }
}
