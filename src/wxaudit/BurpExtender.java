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
import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
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
    private static final Pattern APPID_RE = Pattern.compile("wx[0-9a-fA-F]{16}");
    private static final Pattern WXAPKG_NAME = Pattern.compile("wxapkg|\\.wxapkg|__APP__|app-config", Pattern.CASE_INSENSITIVE);

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
        manualWxid = savedWxid;

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
                ui.refreshStats(0, 0, 0, 0, 0, 0, 0);
                ui.log("结果已清空");
            }
        });

        ui.setScopeText(savedScope);
        ui.setWxidText(savedWxid);
        scope.configure(savedScope);
        ui.setStatus(describeScope());

        callbacks.addSuiteTab(this);
        callbacks.registerProxyListener(this);
        callbacks.printOutput("wxaudit loaded. Configure a target URL in the 'wxaudit' tab to start passive scanning.");
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

    @Override
    public String getTabCaption() { return "wxaudit"; }

    @Override
    public Component getUiComponent() { return ui; }

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
                if (now - lastNoScopeLog > 15000) {   // throttle: avoid log flooding
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

            // remember any appid observed on this host for later decryption
            String observed = findAppId(concat(url.toString(), new String(info.getRequest() == null ? new byte[0]
                    : info.getRequest(), StandardCharsets.ISO_8859_1)));
            if (observed != null) hostAppIds.put(host(url), observed);

            byte[] body = extractBody(raw);
            if (body == null || body.length < 8) return;
            if (Crypto.isGzip(body)) body = gunzip(body);

            List<Scanner.Finding> found;
            String kind;
            if (Crypto.isPlainWxapkg(body)) {
                found = scanWxapkg(body, url, null);
                kind = "wxapkg(明文)";
            } else if (looksLikeEncryptedPackage(url, raw)) {
                String wxid = resolveWxid(url);
                found = scanWxapkg(body, url, wxid);
                kind = "wxapkg(加密)";
            } else if (isTextResponse(url, raw, body)) {
                String text = new String(body, StandardCharsets.UTF_8);
                found = Scanner.scanText(text, pathOf(url), url.toString());
                kind = "JS/文本";
            } else {
                return;
            }

            scannedCount.incrementAndGet();
            if (found != null && !found.isEmpty()) {
                final List<Scanner.Finding> accepted = new ArrayList<Scanner.Finding>();
                for (Scanner.Finding f : found) {
                    if (unique.putIfAbsent(f.key(), new FindingEntry(f)) == null) accepted.add(f);
                }
                if (!accepted.isEmpty()) {
                    final String label = kind;
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override public void run() { ui.addFindings(accepted); }
                    });
                    ui.log("发现 " + accepted.size() + " 条 @ " + label + " " + url);
                }
            }
            updateStats();
        } catch (Throwable t) {
            callbacks.printError("wxaudit scan error: " + t);
            ui.log("扫描异常: " + t.getMessage());
        }
    }

    private List<Scanner.Finding> scanWxapkg(byte[] body, URL url, String wxid) {
        try {
            Wxapkg.UnpackResult result = Wxapkg.unpack(body, wxid);
            List<Scanner.Finding> out = Scanner.scanPackageFiles(result.files, url.toString());
            List<String> routes = Scanner.extractRoutes(result.files);
            if (result.detectedAppId != null) hostAppIds.put(host(url), result.detectedAppId);
            if (!routes.isEmpty()) {
                final List<String> snapshot = routes;
                SwingUtilities.invokeLater(new Runnable() {
                    @Override public void run() { ui.addRoutes(snapshot); }
                });
                ui.log("可疑路由 " + routes.size() + " 个: " + routes);
            }
            ui.log("解包成功 " + url + " (" + result.files.size() + " 文件"
                    + (result.encrypted ? ", 使用 AppID " + wxid : "") + ")");
            return out;
        } catch (Exception ex) {
            // always explain why decryption/unpacking failed
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
        // fallback: mostly printable text
        int printable = 0;
        int sample = Math.min(body.length, 512);
        for (int i = 0; i < sample; i++) {
            int c = body[i] & 0xFF;
            if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) printable++;
        }
        return sample > 0 && printable * 100 / sample > 90;
    }

    private void updateStats() {
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
            @Override public void run() { ui.refreshStats(scanned, skipped, unique.size(), h, m, l, i); }
        });
    }

    private List<FindingEntry> snapshot() {
        return new ArrayList<FindingEntry>(unique.values());
    }

    List<Scanner.Finding> allFindings() {
        List<Scanner.Finding> out = new ArrayList<Scanner.Finding>();
        for (FindingEntry e : snapshot()) out.add(e.finding);
        return out;
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
