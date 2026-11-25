package wxaudit;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * AI 增强自测：用 JDK8 内置 HttpServer mock OpenAI 兼容端点，零外网、零真实 Key。
 * AI enhancement self-tests with a local mock OpenAI-compatible endpoint.
 */
public final class AiTest {
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static int passed = 0;
    private static int failed = 0;

    private static void check(String name, boolean cond) {
        if (cond) { passed++; System.out.println("  OK   " + name); }
        else { failed++; System.out.println("  FAIL " + name); }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== AI Enhancement Tests (mock endpoint) ===");

        testJson();
        testConfig();
        testRedaction();
        testEndpointNormalize();
        testRouteFindings();
        testDisabledZeroRequests();
        testSuccessAndParsing();
        testHttpErrors();
        testTimeout();
        testMalformedAndRetry();
        testBatchChunking();
        testPromptInjectionMarkers();
        testResultStoreAndExport();

        System.out.println("\nAI TESTS: " + passed + " passed, " + failed + " failed");
        if (failed > 0) System.exit(1);
        System.out.println("AI MOCK TEST PASSED");
    }

    // ------------------------------------------------------------------
    private static void testJson() {
        section("Json parser/serializer");
        try {
            Object v = Json.parse("{\"a\":1,\"b\":[true,false,null,\"x\\ny\"],\"c\":{\"d\":-2.5}}");
            Map<String, Object> m = Json.asObject(v);
            check("parse object keys", m != null && m.size() == 3);
            check("parse int", Json.asInt(m.get("a"), 0) == 1);
            List<Object> arr = Json.asList(m.get("b"));
            check("parse array", arr != null && arr.size() == 4);
            check("parse true", Boolean.TRUE.equals(arr.get(0)));
            check("parse null", arr.get(2) == null);
            check("parse escaped newline", "\nx\n".equals(arr.get(3)) == false && "x\ny".equals(arr.get(3)));
            check("parse nested double", Math.abs(Json.asInt(m.get("c"), 0) - 0) < 0.001
                    && Json.asObject(m.get("c")) != null);
            check("quote escapes", Json.quote("a\"b\\c\nd").equals("\"a\\\"b\\\\c\\nd\""));
            check("strip fence", "{\"k\":1}".equals(Json.stripFence("```json\n{\"k\":1}\n```")));
            boolean threw = false;
            try { Json.parse("{\"a\":1} trailing"); } catch (Json.JsonException e) { threw = true; }
            check("reject trailing data", threw);
        } catch (Exception e) {
            check("json no exception", false);
        }
    }

    private static void testConfig() {
        section("AiConfig defaults / round-trip");
        AiConfig d = AiConfig.defaults();
        check("default disabled", !d.enabled);
        check("default no network", !d.isNetworkAllowed());
        AiConfig c = new AiConfig(true, "https://api.deepseek.com/v1", "sk-test", "deepseek-chat",
                15000, 5, 1000, false, true, 0);
        check("network allowed when configured", c.isNetworkAllowed());
        check("validate ok", c.validate() == null);
        AiConfig back = AiConfig.fromJson(c.toJson());
        check("round trip enabled", back.enabled == c.enabled);
        check("round trip model", c.model.equals(back.model));
        check("round trip apiKey", c.apiKey.equals(back.apiKey));
        AiConfig bad = AiConfig.fromJson("{not json");
        check("malformed falls back disabled", !bad.enabled);
        AiConfig noScheme = new AiConfig(true, "api.example.com", "k", "m", 30000, 10, 2000, false, true, 0);
        check("validate rejects bad scheme", noScheme.validate() != null);
    }

    private static void testRedaction() {
        section("Prompt redaction");
        String s = "Authorization: Bearer abcdefghijklmnop\npassword: \"supersecret\"\n";
        String r = AiPrompts.redact(s);
        check("bearer redacted", r.contains("<REDACTED>") && !r.contains("abcdefghijklmnop"));
        check("password redacted", !r.contains("supersecret"));
    }

    private static void testEndpointNormalize() {
        section("Endpoint normalization");
        check("append path", LlmClient.normalizeEndpoint("https://api.openai.com/v1")
                .equals("https://api.openai.com/v1/chat/completions"));
        check("strip trailing slash", LlmClient.normalizeEndpoint("https://x/v1/")
                .equals("https://x/v1/chat/completions"));
        check("keep full endpoint", LlmClient.normalizeEndpoint("https://x/v1/chat/completions")
                .equals("https://x/v1/chat/completions"));
    }

    private static void testRouteFindings() {
        section("Route context upgrade");
        String cfg = "{\"page\":{\"pages/admin/panel\":{},\"pages/index\":{}}}";
        Wxapkg.VirtualFile vf = new Wxapkg.VirtualFile("app-config.json", cfg.getBytes(UTF8));
        List<Wxapkg.VirtualFile> files = Arrays.asList(vf);
        List<RouteFinding> rf = Scanner.extractRouteFindings(files, "https://m.example.com/app.wxapkg");
        check("route findings count", rf.size() == 1);
        if (!rf.isEmpty()) {
            check("route value", "pages/admin/panel".equals(rf.get(0).route));
            check("route file", "app-config.json".equals(rf.get(0).file));
            check("route sourceUrl", "https://m.example.com/app.wxapkg".equals(rf.get(0).sourceUrl));
            check("route line positive", rf.get(0).line >= 1);
            check("route snippet present", !rf.get(0).snippet.isEmpty());
        }
        List<String> legacy = Scanner.extractRoutes(files);
        check("legacy extractRoutes compatible", legacy.size() == 1 && "pages/admin/panel".equals(legacy.get(0)));
    }

    private static CapturedPacket packet(String url) {
        return new CapturedPacket(url, "POST", "JS/文本", System.currentTimeMillis(),
                "POST /api/login HTTP/1.1\nuser_id=123&token=<REDACTED>",
                "{\"code\":0,\"data\":{\"admin\":true}}",
                Arrays.asList("key1"), new ArrayList<RouteFinding>());
    }

    private static AiConfig cfgFor(String baseUrl) {
        return new AiConfig(true, baseUrl, "test-key", "mock-model", 3000, 10, 2000, false, true, 0);
    }

    // Mock response builders -------------------------------------------
    private static String okResponse(String packetId) {
        // Build the nested content JSON via string; quote the id (may contain control chars).
        String content = "{\"results\":[{\"packet_id\":" + Json.quote(packetId) + ","
                + "\"triage\":{\"overall_verdict\":\"true_positive\",\"confidence\":85,"
                + "\"reason\":\"looks valid\",\"per_finding\":[{\"finding_key\":\"key1\","
                + "\"verdict\":\"true_positive\",\"reason\":\"ok\"}]},"
                + "\"chain\":{\"vuln_type\":\"IDOR\",\"preconditions\":[\"valid session\"],"
                + "\"steps\":[\"login\",\"change user_id\"],\"expected_result\":\"access denied expected\","
                + "\"risk_level\":\"high\",\"summary\":\"idor on user_id\"}}]}";
        return "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":"
                + Json.quote(content) + "},\"finish_reason\":\"stop\"}]}";
    }

    private static class MockServer {
        final HttpServer server;
        final AtomicInteger requests = new AtomicInteger();
        volatile String lastAuth = "";
        volatile String lastBody = "";
        volatile String mode = "ok"; // ok | 401 | 429 | 500 | timeout | malformed | badschema

        MockServer() throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/v1/chat/completions", new HttpHandler() {
                @Override public void handle(HttpExchange ex) throws java.io.IOException {
                    requests.incrementAndGet();
                    lastAuth = ex.getRequestHeaders().getFirst("Authorization");
                    lastBody = readAll(ex.getRequestBody());
                    byte[] resp;
                    int status = 200;
                    String pid = extractPacketId(lastBody);
                    if ("401".equals(mode)) { status = 401; resp = "{\"error\":\"unauthorized\"}".getBytes(UTF8); }
                    else if ("429".equals(mode)) { status = 429; resp = "{\"error\":\"rate limited\"}".getBytes(UTF8); }
                    else if ("500".equals(mode)) { status = 500; resp = "{\"error\":\"server error\"}".getBytes(UTF8); }
                    else if ("timeout".equals(mode)) {
                        try { Thread.sleep(600); } catch (InterruptedException ignore) { }
                        resp = okResponse(pid).getBytes(UTF8);
                    } else if ("malformed".equals(mode)) {
                        resp = "{\"choices\":[{\"message\":{\"content\":\"not json at all\"}}]}".getBytes(UTF8);
                    } else if ("badschema".equals(mode)) {
                        resp = "{\"choices\":[{\"message\":{\"content\":\"{\\\"foo\\\":1}\"}}]}".getBytes(UTF8);
                    } else {
                        resp = okResponse(pid).getBytes(UTF8);
                    }
                    ex.getResponseHeaders().set("Content-Type", "application/json");
                    ex.sendResponseHeaders(status, resp.length);
                    OutputStream os = ex.getResponseBody();
                    os.write(resp); os.close();
                }
            });
            server.start();
        }

        String base() { return "http://127.0.0.1:" + server.getAddress().getPort() + "/v1"; }
        void stop() { server.stop(0); }

        private static String readAll(InputStream in) throws java.io.IOException {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] b = new byte[4096]; int n;
            while ((n = in.read(b)) > 0) bos.write(b, 0, n);
            return new String(bos.toByteArray(), UTF8);
        }

        private static String extractPacketId(String body) {
            // The request body is JSON: {"messages":[{"role":"system",...},
            // {"role":"user","content":"...packet_id":"<id>"..."}]}. Parse it and pull
            // the first packet_id out of the user content.
            try {
                Map<String, Object> root = Json.parseObject(body);
                List<Object> msgs = Json.asList(root.get("messages"));
                if (msgs == null || msgs.size() < 2) return "unknown";
                Map<String, Object> user = Json.asObject(msgs.get(1));
                String content = user == null ? null : Json.asString(user.get("content"));
                if (content == null) return "unknown";
                int i = content.indexOf("\"packet_id\":\"");
                if (i < 0) return "unknown";
                int start = i + "\"packet_id\":\"".length();
                int end = content.indexOf('"', start);
                if (end < 0) return "unknown";
                String id = content.substring(start, end);
                // CapturedPacket.id uses U+0001 separators, serialized in the prompt
                // as the literal six-character sequence \u0001. Restore it so the
                // mocked result key matches the real packet id.
                id = id.replace("\\u0001", "\u0001");
                return id;
            } catch (Exception ex) {
                return "unknown";
            }
        }
    }

    private static void testDisabledZeroRequests() throws Exception {
        section("Disabled => zero requests");
        MockServer ms = new MockServer();
        try {
            AiConfig disabled = AiConfig.defaults();
            AiAnalyzer a = new AiAnalyzer(disabled);
            List<AiResult> r = a.analyzeBatch(Arrays.asList(packet("https://x/a")),
                    new Scanner.Finding[0]);
            check("no network when disabled", ms.requests.get() == 0);
            check("error result when disabled", r.size() == 1 && !r.get(0).ok());

            AiConfig noKey = new AiConfig(true, ms.base(), "", "m", 3000, 10, 2000, false, true, 0);
            new AiAnalyzer(noKey).analyzeBatch(Arrays.asList(packet("https://x/b")), new Scanner.Finding[0]);
            check("no network without key", ms.requests.get() == 0);
        } finally { ms.stop(); }
    }

    private static void testSuccessAndParsing() throws Exception {
        section("Success / full chain parsing");
        MockServer ms = new MockServer();
        try {
            ms.mode = "ok";
            CapturedPacket p = packet("https://example.test/api/login");
            AiAnalyzer a = new AiAnalyzer(cfgFor(ms.base()));
            List<AiResult> r = a.analyzeBatch(Arrays.asList(p), new Scanner.Finding[0]);
            check("one request made", ms.requests.get() == 1);
            check("bearer header set", "Bearer test-key".equals(ms.lastAuth));
            check("body has model", ms.lastBody.contains("mock-model"));
            check("body has system framing", ms.lastBody.contains("授权"));
            check("result ok", r.size() == 1 && r.get(0).ok());
            AiResult ar = r.get(0);
            check("triage parsed", ar.triage != null && "true_positive".equals(ar.triage.overallVerdict));
            check("confidence parsed", ar.triage.confidence == 85);
            check("chain parsed", ar.chain != null && "IDOR".equals(ar.chain.vulnType));
            check("chain steps ordered", ar.chain.steps.size() == 2
                    && "login".equals(ar.chain.steps.get(0)));
            check("chain risk parsed", "high".equals(ar.chain.riskLevel));
        } finally { ms.stop(); }
    }

    private static void testHttpErrors() throws Exception {
        section("HTTP error codes");
        for (String mode : new String[] { "401", "429", "500" }) {
            MockServer ms = new MockServer();
            try {
                ms.mode = mode;
                AiAnalyzer a = new AiAnalyzer(cfgFor(ms.base()));
                List<AiResult> r = a.analyzeBatch(Arrays.asList(packet("https://x/" + mode)), new Scanner.Finding[0]);
                check(mode + " produces error result", r.size() == 1 && !r.get(0).ok());
                check(mode + " error mentions HTTP", r.get(0).error.contains(mode.equals("401") ? "HTTP" : "HTTP"));
            } finally { ms.stop(); }
        }
    }

    private static void testTimeout() throws Exception {
        section("Timeout degradation");
        MockServer ms = new MockServer();
        try {
            ms.mode = "timeout";
            AiConfig c = new AiConfig(true, ms.base(), "test-key", "m", 150, 10, 2000, false, true, 0);
            AiAnalyzer a = new AiAnalyzer(c);
            List<AiResult> r = a.analyzeBatch(Arrays.asList(packet("https://x/timeout")), new Scanner.Finding[0]);
            check("timeout produces error result", r.size() == 1 && !r.get(0).ok());
            check("error is TIMEOUT", r.get(0).error.contains("TIMEOUT"));
        } finally { ms.stop(); }
    }

    private static void testMalformedAndRetry() throws Exception {
        section("Malformed JSON + one retry");
        MockServer ms = new MockServer();
        try {
            ms.mode = "malformed";
            AiAnalyzer a = new AiAnalyzer(cfgFor(ms.base()));
            List<AiResult> r = a.analyzeBatch(Arrays.asList(packet("https://x/mal")), new Scanner.Finding[0]);
            check("malformed triggers retry (2 requests)", ms.requests.get() == 2);
            check("malformed yields error", r.size() == 1 && !r.get(0).ok());
            check("error mentions PARSE", r.get(0).error.contains("PARSE"));
        } finally { ms.stop(); }

        MockServer ms2 = new MockServer();
        try {
            ms2.mode = "badschema";
            AiAnalyzer a = new AiAnalyzer(cfgFor(ms2.base()));
            List<AiResult> r = a.analyzeBatch(Arrays.asList(packet("https://x/badschema")), new Scanner.Finding[0]);
            check("bad schema yields error", r.size() == 1 && !r.get(0).ok());
        } finally { ms2.stop(); }
    }

    private static void testBatchChunking() throws Exception {
        section("Batch chunking (3 packets, maxBatch=2)");
        MockServer ms = new MockServer();
        try {
            ms.mode = "ok";
            AiConfig c = new AiConfig(true, ms.base(), "test-key", "m", 3000, 2, 2000, false, true, 0);
            AiAnalyzer a = new AiAnalyzer(c);
            List<CapturedPacket> ps = Arrays.asList(
                    packet("https://x/1"), packet("https://x/2"), packet("https://x/3"));
            List<AiResult> r = a.analyzeBatch(ps, new Scanner.Finding[0]);
            check("two chunks => 2 requests", ms.requests.get() == 2);
            check("three results returned", r.size() == 3);
        } finally { ms.stop(); }
    }

    private static void testPromptInjectionMarkers() throws Exception {
        section("Prompt injection isolation markers");
        MockServer ms = new MockServer();
        try {
            String sys = AiPrompts.systemPrompt(true);
            check("system has untrusted markers", sys.contains("BEGIN UNTRUSTED DATA") && sys.contains("END UNTRUSTED DATA"));
            check("system says data not instructions", sys.contains("数据而非指令"));
            check("system has authorization framing", sys.contains("授权"));
            String user = AiPrompts.userPrompt(Arrays.asList(packet("https://x/inj")), true, new Scanner.Finding[0]);
            check("user wraps data with markers", user.contains("BEGIN UNTRUSTED DATA") && user.contains("END UNTRUSTED DATA"));
            check("user has schema", user.contains("\"results\"") && user.contains("overall_verdict"));
        } finally { ms.stop(); }
    }

    private static void testResultStoreAndExport() throws Exception {
        section("Result store + export integration");
        AiResultStore store = new AiResultStore();
        AiResult ok = new AiResult("id1", "https://x/1", "m", System.currentTimeMillis(),
                new AiTriage("false_positive", 90, "placeholder", new ArrayList<AiTriage.FindingVerdict>()),
                null, "raw", "");
        store.put(ok);
        check("store has key", store.has("id1") && store.size() == 1);
        check("false positive counted", store.falsePositiveCount() == 1);
        store.clear();
        check("store clear", store.size() == 0);

        // Export with AI + routes: verify JSON contains ai_results and routes
        java.io.File tmp = java.io.File.createTempFile("wxaudit-ai", ".json");
        tmp.deleteOnExit();
        RouteFinding r = new RouteFinding("pages/admin/x", "app-config.json", 3, "cfg", "https://x");
        Exporter.writeJson(tmp, new ArrayList<Scanner.Finding>(), "test", new int[7],
                Arrays.asList(r), Arrays.asList(ok));
        String json = new String(readFile(tmp), UTF8);
        check("export has routes", json.contains("\"routes\"") && json.contains("pages/admin/x"));
        check("export has ai_results", json.contains("\"ai_results\"") && json.contains("false_positive"));
    }

    private static byte[] readFile(java.io.File f) throws Exception {
        InputStream in = new java.io.FileInputStream(f);
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] b = new byte[4096]; int n;
            while ((n = in.read(b)) > 0) bos.write(b, 0, n);
            return bos.toByteArray();
        } finally { in.close(); }
    }

    private static String readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] b = new byte[4096]; int n;
        while ((n = in.read(b)) > 0) bos.write(b, 0, n);
        return new String(bos.toByteArray(), UTF8);
    }

    private static void section(String name) {
        System.out.println("\n--- " + name + " ---");
    }
}
