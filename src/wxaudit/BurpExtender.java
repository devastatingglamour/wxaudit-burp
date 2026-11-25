package wxaudit;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IProxyListener;
import burp.IResponseInfo;
import burp.IInterceptedProxyMessage;
import burp.ITab;

import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/**
 * wxaudit Burp extension entry point.
 * Passively scans proxy responses that match the configured target scope.
 * Classic Burp API so it loads on both Community and Pro (JRE 8/11/17/21).
 */
public class BurpExtender implements IBurpExtender, IProxyListener, ITab {

    private static final String SETTING_SCOPE = "wxaudit.scope";
    private static final String SETTING_WXID = "wxaudit.wxid";
    private static final String SETTING_AI = "wxaudit.ai.config";
    private static final Pattern APPID_RE = Pattern.compile("wx[0-9a-fA-F]{16}");
    private static final Pattern WXAPKG_NAME = Pattern.compile("wxapkg|\\.wxapkg|__APP__|app-config", Pattern.CASE_INSENSITIVE);
    private static final int MAX_PACKETS = 2000;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private UiPanel ui;
    private final ScopeFilter scope = new ScopeFilter();
    private final ConcurrentHashMap<String, FindingEntry> unique = new ConcurrentHashMap<String, FindingEntry>();
    private final ConcurrentHashMap<String, String> hostAppIds = new ConcurrentHashMap<String, String>();
    private final AtomicInteger scannedCount = new AtomicInteger();
    private final AtomicInteger skippedCount = new AtomicInteger();
    private volatile String manualWxid = "";
    private volatile long lastNoScopeLog = 0;

    // --- AI / packet capture additions (in-memory only, never persisted) ---
    private final Map<String, CapturedPacket> packets = new LinkedHashMap<String, CapturedPacket>();
    private final ConcurrentLinkedQueue<String> packetFifo = new ConcurrentLinkedQueue<String>();
    private final AiResultStore aiResults = new AiResultStore();
    private volatile AiConfig aiConfig = AiConfig.defaults();
    private AiAnalyzer aiAnalyzer = new AiAnalyzer(aiConfig);
    private volatile ThreadPoolExecutor realtimePool = null;
    private final AtomicBoolean refreshScheduled = new AtomicBoolean(false);

    private static final class FindingEntry {
        final Scanner.Finding finding;
        FindingEntry(Scanner.Finding f) { this.finding = f; }
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("wxaudit - JS / MiniProgram Recon");

        final String savedScope = nullToEmpty(callbacks.loadExtensionSetting(SETTING_SCOPE));
        final String savedWxid = nullToEmpty(callbacks.loadExtensionSetting(SETTING_WXID));
        final String savedAi = nullToEmpty(callbacks.loadExtensionSetting(SETTING_AI));
        manualWxid = savedWxid;
        aiConfig = AiConfig.fromJson(savedAi);
        aiAnalyzer = new AiAnalyzer(aiConfig);

        ui = new UiPanel(new UiPanel.Listener() {
            @Override public void onApply(String scopeText, String wxid) {
                scope.configure(scopeText);
                manualWxid = wxid == null ? "" : wxid.trim();
                callbacks.saveExtensionSetting(SETTING_SCOPE, scopeText == null ? "" : scopeText);
                callbacks.saveExtensionSetting(SETTING_WXID, manualWxid);
                hostAppIds.clear();
                ui.setStatus(describeScope());
                ui.log("目标已更新：" + describeScope() + (manualWxid.isEmpty() ? "" : " | AppID=" + manualWxid));
            }
            @Override public void onClearResults() {
                unique.clear();
                scannedCount.set(0);
                skippedCount.set(0);
                clearPackets();
                ui.clearAll();
                refreshStatsInternal();
                ui.log("结果已清空");
            }
            @Override public void onAiConfigApply(AiConfig cfg) {
                String err = cfg.validate();
                if (err != null) {
                    ui.log("AI 配置未保存: " + err);
                    return;
                }
                aiConfig = cfg;
                aiAnalyzer = new AiAnalyzer(cfg);
                callbacks.saveExtensionSetting(SETTING_AI, cfg.toJson());
                ui.log("AI 配置已保存: " + (cfg.isNetworkAllowed()
                        ? "已启用 " + cfg.model + " @ " + cfg.baseUrl
                        : "已禁用（不会发送任何请求）"));
                if (cfg.realtime && cfg.isNetworkAllowed()) ensureRealtimePool();
                else shutdownRealtimePool();
            }
            @Override public void onAnalyzeSelected(final List<String> packetIds) {
                analyzeSelected(packetIds);
            }
        });

        ui.setScopeText(savedScope);
        ui.setWxidText(savedWxid);
        ui.setAiConfig(aiConfig);
        scope.configure(savedScope);
        ui.setStatus(describeScope());

        callbacks.addSuiteTab(this);
        callbacks.registerProxyListener(this);
        callbacks.printOutput("wxaudit loaded. AI enhancement "
                + (aiConfig.isNetworkAllowed() ? "ENABLED (" + aiConfig.model + ")" : "disabled (default)"));
    }

    private String describeScope() {
        if (!scope.isConfigured()) return "未配置目标 - 当前不扫描任何数据包";
        List<ScopeFilter.Entry> entries = scope.entries();
        StringBuilder sb = new StringBuilder("目标 " + entries.size() + " 个: ");
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(entries.get(i).raw);
        }
        return sb.toString();
    }

    @Override public String getTabCaption() { return "wxaudit"; }
    @Override public Component getUiComponent() { return ui; }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (messageIsRequest) return;   // only analyze responses
        try {
            IHttpRequestResponse info = message.getMessageInfo();
            if (info == null) return;
            byte[] raw = info.getResponse();
            if (raw == null || raw.length < 32) return;
            URL url = info.getUrl();
            if (url == null) return;

            if (!scope.isConfigured()) {
                long now = System.currentTimeMillis();
                if (now - lastNoScopeLog > 15000) {
                    ui.log("跳过 " + host(url) + "（未配置目标网址，请在面板填写后点“应用目标”）");
                    lastNoScopeLog = now;
                }
                skippedCount.incrementAndGet();
                return;
            }
            if (!scope.matches(url)) {
                skippedCount.incrementAndGet();
                return;
            }
            if (raw.length > Scanner.MAX_SCAN_BYTES) {
                ui.log("跳过过大响应 " + url + " (" + raw.length + " bytes)");
                skippedCount.incrementAndGet();
                return;
            }

            byte[] requestBytes = info.getRequest();
            String requestText = new String(requestBytes == null ? new byte[0] : requestBytes,
                    StandardCharsets.ISO_8859_1);
            String observed = findAppId(concat(url.toString(), requestText));
            if (observed != null) hostAppIds.put(host(url), observed);

            byte[] body = extractBody(raw);
            if (body == null || body.length < 8) return;
            if (Crypto.isGzip(body)) body = gunzip(body);

            List<Scanner.Finding> found;
            String kind;
            List<RouteFinding> packetRoutes = new ArrayList<RouteFinding>();
            if (Crypto.isPlainWxapkg(body)) {
                found = scanWxapkg(body, url, null, packetRoutes);
                kind = "wxapkg(明文)";
            } else if (looksLikeEncryptedPackage(url, raw)) {
                String wxid = resolveWxid(url);
                found = scanWxapkg(body, url, wxid, packetRoutes);
                kind = "wxapkg(加密)";
            } else if (isTextResponse(url, raw, body)) {
                String text = new String(body, StandardCharsets.UTF_8);
                found = Scanner.scanText(text, pathOf(url), url.toString());
                kind = "JS/文本";
            } else {
                return;
            }

            scannedCount.incrementAndGet();
            final List<Scanner.Finding> accepted = new ArrayList<Scanner.Finding>();
            if (found != null && !found.isEmpty()) {
                for (Scanner.Finding f : found) {
                    if (unique.putIfAbsent(f.key(), new FindingEntry(f)) == null) accepted.add(f);
                }
            }

            // Build captured packet (redacted, in-memory) even with zero findings,
            // so the user can still select it for AI analysis.
            String method = parseMethod(requestText);
            String requestHead = redactRequestHead(requestText);
            String responseExcerpt = AiPrompts.redact(
                    new String(body, 0, Math.min(body.length, 2000), StandardCharsets.UTF_8));
            List<String> fkeys = new ArrayList<String>();
            for (Scanner.Finding f : accepted) fkeys.add(f.key());
            final CapturedPacket packet = new CapturedPacket(
                    url.toString(), method, kind, System.currentTimeMillis(),
                    requestHead, responseExcerpt, fkeys, packetRoutes);
            recordPacket(packet);

            if (!accepted.isEmpty()) {
                ui.log("发现 " + accepted.size() + " 条 @ " + kind + " " + url);
            }
            final List<Scanner.Finding> acceptedSnapshot = accepted;
            SwingUtilities.invokeLater(new Runnable() {
                @Override public void run() {
                    ui.addFindings(acceptedSnapshot);
                    ui.addPacket(packet);
                }
            });

            // Optional realtime AI (off by default). Never blocks the proxy thread.
            if (aiConfig.realtime && aiConfig.isNetworkAllowed() && realtimePool != null) {
                try {
                    realtimePool.execute(new Runnable() {
                        @Override public void run() { realtimeAnalyze(packet); }
                    });
                } catch (java.util.concurrent.RejectedExecutionException re) {
                    ui.log("AI 实时队列已满，丢弃一条（可关闭实时分析）");
                }
            }
            updateStats();
        } catch (Throwable t) {
            callbacks.printError("wxaudit scan error: " + t);
            ui.log("扫描异常: " + t.getMessage());
        }
    }

    private List<Scanner.Finding> scanWxapkg(byte[] body, URL url, String wxid,
                                              List<RouteFinding> outRoutes) {
        try {
            Wxapkg.UnpackResult result = Wxapkg.unpack(body, wxid);
            List<Scanner.Finding> out = Scanner.scanPackageFiles(result.files, url.toString());
            List<RouteFinding> routes = Scanner.extractRouteFindings(result.files, url.toString());
            if (result.detectedAppId != null) hostAppIds.put(host(url), result.detectedAppId);
            if (outRoutes != null && routes != null) outRoutes.addAll(routes);
            if (!routes.isEmpty()) {
                final List<RouteFinding> snapshot = new ArrayList<RouteFinding>(routes);
                SwingUtilities.invokeLater(new Runnable() {
                    @Override public void run() { ui.addRoutes(snapshot); }
                });
                ui.log("可疑路由 " + routes.size() + " 个");
            }
            ui.log("解包成功 " + url + " (" + result.files.size() + " 文件"
                    + (result.encrypted ? ", 使用 AppID " + wxid : "") + ")");
            return out;
        } catch (Exception ex) {
            ui.log("解包失败 " + url + " -> " + ex.getMessage());
            return null;
        }
    }

    private String resolveWxid(URL url) {
        if (!manualWxid.isEmpty()) return manualWxid;
        String observed = hostAppIds.get(host(url));
        if (observed != null) return observed;
        ui.log("加密包无法解密：" + host(url) + " 未提取到 AppID，请在面板手动填入 wxid 后重放该请求");
        return null;
    }

    private byte[] extractBody(byte[] raw) {
        IResponseInfo ri = helpers.analyzeResponse(raw);
        int off = ri.getBodyOffset();
        if (off <= 0 || off >= raw.length) return null;
        byte[] body = new byte[raw.length - off];
        System.arraycopy(raw, off, body, 0, body.length);
        return body;
    }

    private static byte[] gunzip(byte[] data) {
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(data);
            GZIPInputStream gz = new GZIPInputStream(in);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = gz.read(buf)) > 0) out.write(buf, 0, n);
            gz.close();
            return out.toByteArray();
        } catch (Exception ex) {
            return data;
        }
    }

    private boolean looksLikeEncryptedPackage(URL url, byte[] raw) {
        String head = new String(raw, 0, Math.min(raw.length, 4096), StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        return WXAPKG_NAME.matcher(url.toString()).find() || head.contains("wxapkg") || head.contains("content-disposition");
    }

    private boolean isTextResponse(URL url, byte[] raw, byte[] body) {
        String path = pathOf(url).toLowerCase(Locale.ROOT);
        if (Scanner.isScannableName(path)) return true;
        String head = new String(raw, 0, Math.min(raw.length, 4096), StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        if (head.contains("content-type:")) return head.contains("javascript") || head.contains("ecmascript")
                || head.contains("json") || head.contains("text/") || head.contains("x-www-form-urlencoded");
        int printable = 0;
        int sample = Math.min(body.length, 512);
        for (int i = 0; i < sample; i++) {
            int c = body[i] & 0xFF;
            if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) printable++;
        }
        return sample > 0 && printable * 100 / sample > 90;
    }

    private void updateStats() {
        refreshStatsInternal();
    }

    private void refreshStatsInternal() {
        final int scanned = scannedCount.get();
        final int skipped = skippedCount.get();
        int high = 0, medium = 0, low = 0, info = 0;
        for (FindingEntry e : unique.values()) {
            String s = e.finding.severity;
            if ("high".equals(s)) high++;
            else if ("medium".equals(s)) medium++;
            else if ("low".equals(s)) low++;
            else info++;
        }
        final int h = high, m = medium, l = low, i = info;
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() {
                ui.refreshStats(scanned, skipped, unique.size(), h, m, l, i);
                ui.setAiStats(aiResults.size(), packets.size(), aiResults.falsePositiveCount());
            }
        });
    }

    // ------------------------------------------------------------------
    // Packet capture (in-memory, bounded)
    private synchronized void recordPacket(CapturedPacket p) {
        packets.put(p.id, p);
        packetFifo.offer(p.id);
        while (packetFifo.size() > MAX_PACKETS) {
            String old = packetFifo.poll();
            if (old != null) packets.remove(old);
        }
    }

    private synchronized void clearPackets() {
        packets.clear();
        packetFifo.clear();
        aiResults.clear();
    }

    synchronized List<CapturedPacket> packetsByIds(List<String> ids) {
        List<CapturedPacket> out = new ArrayList<CapturedPacket>();
        if (ids == null) return out;
        for (String id : ids) {
            CapturedPacket p = packets.get(id);
            if (p != null) out.add(p);
        }
        return out;
    }

    synchronized List<CapturedPacket> allPackets() {
        return new ArrayList<CapturedPacket>(packets.values());
    }

    Scanner.Finding[] allFindingsArray() {
        List<Scanner.Finding> list = allFindings();
        return list.toArray(new Scanner.Finding[list.size()]);
    }

    // ------------------------------------------------------------------
    // AI analysis
    private void analyzeSelected(final List<String> packetIds) {
        if (!aiConfig.isNetworkAllowed()) {
            ui.log("AI 未启用：请先在面板填写 base_url / API Key / 模型并勾选启用");
            return;
        }
        final List<CapturedPacket> selected = packetsByIds(packetIds);
        if (selected.isEmpty()) {
            ui.log("未选中任何数据包");
            return;
        }
        final List<CapturedPacket> todo = new ArrayList<CapturedPacket>();
        for (CapturedPacket p : selected) if (!aiResults.has(p.id)) todo.add(p);
        if (todo.isEmpty()) {
            ui.log("选中的数据包均已分析（可在详情区查看）");
            return;
        }
        final String model = aiConfig.model;
        ui.log("AI 开始分析 " + todo.size() + " 个数据包 (" + model + ")");
        new SwingWorker<List<AiResult>, Void>() {
            @Override protected List<AiResult> doInBackground() {
                return aiAnalyzer.analyzeBatch(todo, allFindingsArray());
            }
            @Override protected void done() {
                try {
                    List<AiResult> results = get();
                    int ok = 0, err = 0;
                    for (AiResult r : results) {
                        aiResults.put(r);
                        if (r.ok()) ok++; else err++;
                    }
                    ui.setAiResults(aiResults);
                    refreshStatsInternal();
                    ui.log("AI 完成: 成功 " + ok + " / 失败 " + err);
                } catch (Exception ex) {
                    ui.log("AI 分析失败: " + ex.getMessage());
                }
            }
        }.execute();
    }

    private void realtimeAnalyze(CapturedPacket packet) {
        if (aiResults.has(packet.id)) return;
        AiResult r = aiAnalyzer.analyzeOne(packet, allFindingsArray());
        aiResults.put(r);
        scheduleAiRefresh();
    }

    private void scheduleAiRefresh() {
        if (!refreshScheduled.compareAndSet(false, true)) return;
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() {
                refreshScheduled.set(false);
                ui.setAiResults(aiResults);
                refreshStatsInternal();
            }
        });
    }

    private void ensureRealtimePool() {
        if (realtimePool != null && !realtimePool.isShutdown()) return;
        realtimePool = new ThreadPoolExecutor(1, 2, 60L, TimeUnit.SECONDS,
                new java.util.concurrent.ArrayBlockingQueue<Runnable>(50),
                new ThreadPoolExecutor.DiscardOldestPolicy());
        realtimePool.setThreadFactory(new java.util.concurrent.ThreadFactory() {
            private final AtomicInteger n = new AtomicInteger();
            @Override public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "wxaudit-ai-" + n.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        });
    }

    private void shutdownRealtimePool() {
        ThreadPoolExecutor pool = realtimePool;
        if (pool != null && !pool.isShutdown()) pool.shutdownNow();
        realtimePool = null;
    }

    // ------------------------------------------------------------------
    List<Scanner.Finding> allFindings() {
        List<Scanner.Finding> out = new ArrayList<Scanner.Finding>();
        for (FindingEntry e : unique.values()) out.add(e.finding);
        return out;
    }

    List<RouteFinding> allRoutes() { return ui == null ? new ArrayList<RouteFinding>() : ui.routesSnapshot(); }

    List<AiResult> allAiResults() { return aiResults.all(); }

    private static String parseMethod(String requestText) {
        if (requestText == null || requestText.isEmpty()) return "GET";
        int sp = requestText.indexOf(' ');
        String m = sp > 0 ? requestText.substring(0, sp) : "GET";
        return m.length() > 12 ? "GET" : m.toUpperCase(Locale.ROOT);
    }

    private static String redactRequestHead(String requestText) {
        if (requestText == null || requestText.isEmpty()) return "";
        int end = requestText.indexOf("\r\n\r\n");
        if (end < 0) end = requestText.indexOf("\n\n");
        String head = end > 0 ? requestText.substring(0, end) : requestText;
        return AiPrompts.redact(head.length() > 1000 ? head.substring(0, 1000) : head);
    }

    private static String findAppId(String text) {
        Matcher m = APPID_RE.matcher(text);
        return m.find() ? m.group() : null;
    }

    private static String concat(String a, String b) { return a + "\n" + b; }
    private static String nullToEmpty(String s) { return s == null ? "" : s; }
    private static String host(URL u) { return u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT); }
    private static String pathOf(URL u) { return u.getPath() == null ? "/" : u.getPath(); }
}
