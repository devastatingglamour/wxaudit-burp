package wxaudit;

/**
 * 单个数据包的 AI 分析结果信封 / AI result envelope for one captured packet.
 *
 * <p>同时承载误报研判与利用链；任一失败时保留 raw/error 供降级展示。
 * Carries both triage and exploit chain; keeps raw/error on failure for graceful degradation.
 */
public final class AiResult {
    public final String packetId;
    public final String sourceUrl;
    public final String model;
    public final long timestamp;
    public final AiTriage triage;
    public final AiChain chain;
    public final String raw;
    public final String error;

    public AiResult(String packetId, String sourceUrl, String model, long timestamp,
                    AiTriage triage, AiChain chain, String raw, String error) {
        this.packetId = packetId == null ? "" : packetId;
        this.sourceUrl = sourceUrl == null ? "" : sourceUrl;
        this.model = model == null ? "" : model;
        this.timestamp = timestamp;
        this.triage = triage;
        this.chain = chain;
        this.raw = raw == null ? "" : raw;
        this.error = error == null ? "" : error;
    }

    /** 成功 = 无错误且有研判或利用链之一。 */
    public boolean ok() {
        return error.isEmpty() && (triage != null || chain != null);
    }

    public static AiResult errorResult(String packetId, String sourceUrl, String model, String error) {
        return new AiResult(packetId, sourceUrl, model, System.currentTimeMillis(),
                null, null, "", error);
    }
}
