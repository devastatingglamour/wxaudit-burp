package wxaudit;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * AI 分析编排层 / AI analysis orchestrator.
 *
 * <p>负责：分块批量分析、prompt 构建、响应解析、失败重试一次、结果归位。
 * 网络调用由调用方放到后台线程（SwingWorker 或线程池），本类不管理线程。
 */
public final class AiAnalyzer {

    private final AiConfig config;
    private final LlmClient client;

    public AiAnalyzer(AiConfig config) {
        this.config = config == null ? AiConfig.defaults() : config;
        this.client = new LlmClient(this.config);
    }

    /** 供外部检查是否可联网。 */
    public boolean networkAllowed() {
        return config.isNetworkAllowed();
    }

    /**
     * 批量分析：按 maxBatch 分块，每块一次调用。返回与输入包一一对应的结果列表。
     * 解析失败自动重试一次（附修复提示）；仍失败则生成 error 结果。
     */
    public List<AiResult> analyzeBatch(List<CapturedPacket> packets, Scanner.Finding[] findingsByKey) {
        List<AiResult> results = new ArrayList<AiResult>();
        if (packets == null || packets.isEmpty()) return results;
        if (!config.isNetworkAllowed()) {
            for (CapturedPacket p : packets) {
                results.add(AiResult.errorResult(p.id, p.sourceUrl, config.model, "AI 未启用或未配置"));
            }
            return results;
        }

        int batch = config.maxBatch;
        for (int start = 0; start < packets.size(); start += batch) {
            int end = Math.min(start + batch, packets.size());
            List<CapturedPacket> chunk = packets.subList(start, end);
            results.addAll(analyzeChunk(chunk, findingsByKey, false));
        }
        return results;
    }

    /** 分析单个包（实时模式用）。 */
    public AiResult analyzeOne(CapturedPacket packet, Scanner.Finding[] findingsByKey) {
        List<CapturedPacket> one = Collections.singletonList(packet);
        List<AiResult> r = analyzeChunk(one, findingsByKey, false);
        return r.isEmpty() ? AiResult.errorResult(packet.id, packet.sourceUrl, config.model, "empty result") : r.get(0);
    }

    private List<AiResult> analyzeChunk(List<CapturedPacket> chunk,
                                        Scanner.Finding[] findingsByKey, boolean retry) {
        List<AiResult> out = new ArrayList<AiResult>();
        String system = AiPrompts.systemPrompt(config.exploitChain);
        String user = AiPrompts.userPrompt(chunk, config.exploitChain, findingsByKey);
        if (retry) user += AiPrompts.repairInstruction();

        String response;
        try {
            response = client.chat(system, user);
        } catch (LlmClient.LlmException le) {
            String msg = le.kind + (le.statusCode > 0 ? " " + le.statusCode : "") + ": " + le.getMessage();
            for (CapturedPacket p : chunk) out.add(AiResult.errorResult(p.id, p.sourceUrl, config.model, msg));
            return out;
        }

        String content;
        try {
            content = LlmClient.extractContent(response);
        } catch (LlmClient.LlmException le) {
            if (!retry) return analyzeChunk(chunk, findingsByKey, true);
            for (CapturedPacket p : chunk)
                out.add(AiResult.errorResult(p.id, p.sourceUrl, config.model, "PARSE: " + le.getMessage()));
            return out;
        }

        Map<String, AiAnalyzerParsed> parsed;
        try {
            parsed = parseResults(content);
        } catch (Exception ex) {
            if (!retry) return analyzeChunk(chunk, findingsByKey, true);
            for (CapturedPacket p : chunk)
                out.add(AiResult.errorResult(p.id, p.sourceUrl, config.model,
                        "PARSE: " + ex.getMessage()));
            return out;
        }

        for (CapturedPacket p : chunk) {
            AiAnalyzerParsed pr = parsed.get(p.id);
            if (pr == null) {
                out.add(AiResult.errorResult(p.id, p.sourceUrl, config.model, "no result for packet"));
            } else {
                out.add(new AiResult(p.id, p.sourceUrl, config.model, System.currentTimeMillis(),
                        pr.triage, pr.chain, content, ""));
            }
        }
        return out;
    }

    /** 解析结果条目内部承载类。 */
    public static final class AiAnalyzerParsed {
        public final AiTriage triage;
        public final AiChain chain;
        public AiAnalyzerParsed(AiTriage triage, AiChain chain) {
            this.triage = triage;
            this.chain = chain;
        }
    }

    /** 从模型 JSON 中解析 packet_id → 结论映射。 */
    static Map<String, AiAnalyzerParsed> parseResults(String content) throws Json.JsonException {
        Map<String, Object> root = Json.parseObject(Json.stripFence(content));
        List<Object> results = Json.asList(root.get("results"));
        if (results == null) throw new Json.JsonException("no results array");
        Map<String, AiAnalyzerParsed> out = new HashMap<String, AiAnalyzerParsed>();
        for (Object item : results) {
            Map<String, Object> obj = Json.asObject(item);
            if (obj == null) continue;
            String packetId = Json.asString(obj.get("packet_id"));
            if (packetId == null || packetId.isEmpty()) continue;
            out.put(packetId, new AiAnalyzerParsed(
                    parseTriage(Json.asObject(obj.get("triage"))),
                    parseChain(Json.asObject(obj.get("chain")))));
        }
        return out;
    }

    private static AiTriage parseTriage(Map<String, Object> obj) {
        if (obj == null) return null;
        String verdict = Json.asString(obj.get("overall_verdict"));
        int confidence = Json.asInt(obj.get("confidence"), 0);
        String reason = Json.asString(obj.get("reason"));
        List<AiTriage.FindingVerdict> fvs = new ArrayList<AiTriage.FindingVerdict>();
        List<Object> arr = Json.asList(obj.get("per_finding"));
        if (arr != null) {
            for (Object o : arr) {
                Map<String, Object> m = Json.asObject(o);
                if (m == null) continue;
                fvs.add(new AiTriage.FindingVerdict(
                        Json.asString(m.get("finding_key")),
                        Json.asString(m.get("verdict")),
                        Json.asString(m.get("reason"))));
            }
        }
        return new AiTriage(verdict, confidence, reason, fvs);
    }

    private static AiChain parseChain(Map<String, Object> obj) {
        if (obj == null) return null;
        return new AiChain(
                Json.asString(obj.get("vuln_type")),
                strList(obj.get("preconditions")),
                strList(obj.get("steps")),
                Json.asString(obj.get("expected_result")),
                Json.asString(obj.get("risk_level")),
                Json.asString(obj.get("summary")));
    }

    private static List<String> strList(Object o) {
        List<String> out = new ArrayList<String>();
        List<Object> arr = Json.asList(o);
        if (arr != null) for (Object x : arr) if (x instanceof String) out.add((String) x);
        return out;
    }

    /** 关闭实时线程池（若由外部持有）。 */
    public static void shutdownPool(ThreadPoolExecutor pool) {
        if (pool != null && !pool.isShutdown()) pool.shutdownNow();
    }
}
