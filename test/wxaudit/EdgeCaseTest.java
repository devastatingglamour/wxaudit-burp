package wxaudit;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IInterceptedProxyMessage;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPOutputStream;

/** Boundary, malformed-input and regression checks. */
public class EdgeCaseTest {

    static int failed = 0;

    static void check(boolean ok, String label) {
        System.out.println((ok ? "  OK   " : "  FAIL ") + label);
        if (!ok) failed++;
    }

    @SuppressWarnings("unchecked")
    static <T> T mock(Class<T> iface, InvocationHandler h) {
        return (T) Proxy.newProxyInstance(EdgeCaseTest.class.getClassLoader(), new Class<?>[]{iface}, h);
    }

    static Object def(Class<?> t) {
        if (!t.isPrimitive()) return null;
        if (t == boolean.class) return false;
        if (t == int.class) return 0;
        if (t == short.class) return (short) 0;
        if (t == byte.class) return (byte) 0;
        if (t == long.class) return 0L;
        return null;
    }

    static void testScope() {
        System.out.println("A) Scope boundary cases");
        ScopeFilter sf = new ScopeFilter();
        sf.configure(null);
        check(!sf.isConfigured() && sf.entries().isEmpty(), "null config => no targets");
        sf.configure("  \n # comment\n // comment\n , ; \n");
        check(!sf.isConfigured(), "blank/comment-only config => no targets");
        sf.configure("EXAMPLE.COM\n10.0.0.1\nhttps://h.com/app/v1\n*.a.com");
        check(sf.matches("https://sub.example.com/x"), "host match is case-insensitive");
        check(sf.matches("http://10.0.0.1:8080/x"), "IP host with port matched by host field");
        check(sf.matches("https://h.com/app/v1"), "exact path matched");
        check(sf.matches("https://h.com/app/v1/page"), "path prefix with slash matched");
        check(!sf.matches("https://h.com/app/v10/page"), "path prefix does NOT match /app/v10");
        check(!sf.matches("https://h.com/other"), "other path rejected");
        check(sf.matches("https://x.a.com/"), "*.a.com subdomain matched");
        check(!sf.matches("https://notaa.com/"), "*.a.com does not match notaa.com");
        check(!sf.matches("https://a.com.evil.net/"), "suffix confusion rejected");
        check(!sf.matches("javascript:alert(1)"), "non-http scheme rejected");
    }

    static void testCrypto() {
        System.out.println("B) Crypto / package malformed input");
        check(!Crypto.isPlainWxapkg(null), "null is not a package");
        check(!Crypto.isPlainWxapkg(new byte[0]), "empty bytes not a package");
        check(!Crypto.isPlainWxapkg(new byte[17]), "truncated header not a package");
        check(Crypto.isGzip(new byte[]{0x1f, (byte) 0x8b, 0x00}), "gzip magic detected");
        check(!Crypto.isGzip(new byte[]{0x00, 0x01}), "random bytes not gzip");
        boolean shortRejected = false;
        try { Crypto.decryptWxapkg(new byte[10], "wx1234567890abcdef"); }
        catch (Exception ex) { shortRejected = true; }
        check(shortRejected, "short encrypted package rejected");
        boolean badIdRejected = false;
        try { Crypto.decryptWxapkg(new byte[2048], "wx"); }
        catch (Exception ex) { badIdRejected = true; }
        check(badIdRejected, "too-short AppID rejected");

        List<Wxapkg.VirtualFile> files = new ArrayList<Wxapkg.VirtualFile>();
        files.add(new Wxapkg.VirtualFile("app-config.json",
                "{\"page\":{\"pages/index/index\":{}}}".getBytes(StandardCharsets.UTF_8)));
        byte[] pkg = Wxapkg.buildPlainPackage(files);
        Wxapkg.UnpackResult r = null;
        try { r = Wxapkg.unpack(pkg, null); }
        catch (Exception ex) { check(false, "valid package parses: " + ex.getMessage()); }
        if (r != null) check(r.files.size() == 1 && r.detectedAppId == null, "no appid => null, no crash");
    }

    static void testScanner() {
        System.out.println("C) Scanner boundaries");
        check(Scanner.scanText(null, "x", "u").isEmpty(), "null text => no findings");
        check(Scanner.scanText("", "x", "u").isEmpty(), "empty text => no findings");
        List<Scanner.Finding> f = Scanner.scanText(
                "var ak='LTAI5tABCDEFGHIJKLMNOP';\nvar ak2='LTAI5tABCDEFGHIJKLMNOP';", "a.js", "u");
        check(f.size() == 2, "same value on different lines kept");
        List<Scanner.Finding> f2 = Scanner.scanText(
                "var a='LTAI5tABCDEFGHIJKLMNOP'; var b='LTAI5tABCDEFGHIJKLMNOP';", "a.js", "u");
        check(f2.size() == 1, "same value on same line de-duplicated");
        StringBuilder longVal = new StringBuilder();
        for (int i = 0; i < 150; i++) longVal.append('A');
        List<Scanner.Finding> f3 = Scanner.scanText("var secret='" + longVal + "';", "a.js", "u");
        check(!f3.isEmpty() && f3.get(0).value.length() == 150, "long value captured intact (truncation guard at 300)");
        check(Rules.isIgnored("abs_url", "http://example.com/x"), "noise domain ignored");
        check(Rules.isIgnored("phone", "true"), "placeholder value ignored");
        check(Rules.isIgnored("wx_request", "/pages/index/index"), "frontend route ignored");
        check(!Rules.isIgnored("abs_url", "https://api.target-corp.cn/v1"), "real URL not ignored");
        check(Scanner.extractRoutes(new ArrayList<Wxapkg.VirtualFile>()).isEmpty(), "no config => no routes");
        check(Scanner.isScannableName("app.js?v=1"), "query string stripped for extension check");
        check(!Scanner.isScannableName("image.png"), "binary extension not scannable");

        // oversized unpacked file skipped
        byte[] big = new byte[Scanner.MAX_SCAN_BYTES + 100];
        Arrays.fill(big, (byte) 'A');
        List<Wxapkg.VirtualFile> bigFiles = Arrays.asList(new Wxapkg.VirtualFile("big.js", big));
        check(Scanner.scanPackageFiles(bigFiles, "u").isEmpty(), "oversized file skipped without OOM");
        check(Scanner.scanPackageFiles(null, "u").isEmpty(), "null file list handled");
    }

    static void testExporter() throws Exception {
        System.out.println("D) Report escaping");
        File dir = Files.createTempDirectory("wxaudit-edge").toFile();
        List<Scanner.Finding> fs = new ArrayList<Scanner.Finding>();
        fs.add(new Scanner.Finding("rule", "name", "high", "secret",
                "abc\"def\\ghi\n<script>alert(1)</script>", "a.js", 3, "<b>ctx</b>", "note", "https://h.com/?a=1&b=2"));
        int[] stats = {1, 2, 1, 1, 0, 0, 0};
        File jf = new File(dir, "r.json");
        File hf = new File(dir, "r.html");
        Exporter.writeJson(jf, fs, "target \"X\"", stats);
        Exporter.writeHtml(hf, fs, "target \"X\"", stats);
        String json = new String(Files.readAllBytes(jf.toPath()), StandardCharsets.UTF_8);
        String html = new String(Files.readAllBytes(hf.toPath()), StandardCharsets.UTF_8);
        check(json.contains("\\\"") && json.contains("\\\\") && json.contains("\\n"), "JSON escapes quote/backslash/newline");
        check(json.contains("\"severity_counts\"") && json.contains("\"finding_count\": 1"), "JSON structure present");
        check(!html.contains("<script>alert"), "HTML escapes script tag");
        check(html.contains("&lt;b&gt;ctx&lt;/b&gt;"), "HTML escapes context snippet");
        check(html.contains("&amp;"), "HTML escapes ampersand in source URL");
        check(html.contains("wxaudit") && html.contains("高危"), "HTML report labels present");
    }

    static void testExtender() throws Exception {
        System.out.println("E) Passive listener edge cases");
        final IExtensionHelpers helpers = mock(IExtensionHelpers.class, new InvocationHandler() {
            @Override public Object invoke(Object p, Method m, Object[] a) {
                if ("analyzeResponse".equals(m.getName())) {
                    final byte[] raw = (byte[]) a[0];
                    int off = 0;
                    for (int i = 0; i + 3 < raw.length; i++) {
                        if (raw[i] == 13 && raw[i + 1] == 10 && raw[i + 2] == 13 && raw[i + 3] == 10) {
                            off = i + 4; break;
                        }
                    }
                    final int o = off;
                    return mock(IResponseInfo.class, new InvocationHandler() {
                        @Override public Object invoke(Object p2, Method m2, Object[] a2) {
                            return "getBodyOffset".equals(m2.getName()) ? o : def(m2.getReturnType());
                        }
                    });
                }
                return def(m.getReturnType());
            }
        });
        final Map<String, String> settings = new HashMap<String, String>();
        settings.put("wxaudit.scope", "target-corp.cn");
        IBurpExtenderCallbacks cb = mock(IBurpExtenderCallbacks.class, new InvocationHandler() {
            @Override public Object invoke(Object p, Method m, Object[] a) {
                if ("getHelpers".equals(m.getName())) return helpers;
                if ("loadExtensionSetting".equals(m.getName())) return settings.get(a[0]);
                return def(m.getReturnType());
            }
        });
        BurpExtender ext = new BurpExtender();
        ext.registerExtenderCallbacks(cb);
        Field uniqueField = BurpExtender.class.getDeclaredField("unique");
        uniqueField.setAccessible(true);
        ConcurrentHashMap<?, ?> unique = (ConcurrentHashMap<?, ?>) uniqueField.get(ext);

        byte[] js = "var ak='LTAI5tABCDEFGHIJKLMNOP';".getBytes(StandardCharsets.UTF_8);
        byte[] resp = http("application/javascript", js);
        ext.processProxyMessage(false, msg(new URL("https://a.target-corp.cn/a.js"), resp));
        int n1 = unique.size();
        check(n1 > 0, "first in-scope response recorded");
        ext.processProxyMessage(false, msg(new URL("https://a.target-corp.cn/a.js"), resp));
        check(unique.size() == n1, "identical response de-duplicated");

        ext.processProxyMessage(true, msg(new URL("https://a.target-corp.cn/a.js"), resp));
        check(unique.size() == n1, "request-phase messages ignored");
        ext.processProxyMessage(false, msg(new URL("https://a.target-corp.cn/a.js"), null));
        check(unique.size() == n1, "null response ignored without crash");

        byte[] huge = new byte[Scanner.MAX_SCAN_BYTES + 10];
        Arrays.fill(huge, (byte) 'a');
        ext.processProxyMessage(false, msg(new URL("https://a.target-corp.cn/big.js"), http("application/javascript", huge)));
        check(unique.size() == n1, "oversized HTTP response skipped");

        byte[] gzBody = gzip("var ak='LTAI5tABCDEFGHIJKLMNOP';".getBytes(StandardCharsets.UTF_8));
        ext.processProxyMessage(false, msg(new URL("https://a.target-corp.cn/a.js"), http("application/javascript", gzBody)));
        check(unique.size() == n1, "gzip body decompresses to already-seen finding (no duplicate)");

        byte[] binary = new byte[]{0x00, 0x01, 0x02, 0x03, (byte) 0xff, (byte) 0xfe, 0x00, 0x7f};
        ext.processProxyMessage(false, msg(new URL("https://a.target-corp.cn/blob"), http("application/octet-stream", binary)));
        check(unique.size() == n1, "binary body skipped");

        ext.processProxyMessage(false, msg(null, resp));
        check(unique.size() == n1, "null URL ignored without crash");

        UiPanel ui = new UiPanel(new UiPanel.Listener() {
            @Override public void onApply(String s, String w) { }
            @Override public void onClearResults() { }
        });
        ui.addFindings(null);
        ui.log(null);
        ui.setScopeText(null);
        ui.setWxidText(null);
        check(true, "UI null arguments tolerated");
    }

    static byte[] http(String ct, byte[] body) {
        String head = "HTTP/1.1 200 OK\r\nContent-Type: " + ct + "\r\n\r\n";
        byte[] h = head.getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = new byte[h.length + body.length];
        System.arraycopy(h, 0, out, 0, h.length);
        System.arraycopy(body, 0, out, h.length, body.length);
        return out;
    }

    static byte[] gzip(byte[] data) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        GZIPOutputStream gz = new GZIPOutputStream(bos);
        gz.write(data); gz.close();
        return bos.toByteArray();
    }

    static IInterceptedProxyMessage msg(final URL url, final byte[] response) {
        final IHttpRequestResponse rr = mock(IHttpRequestResponse.class, new InvocationHandler() {
            @Override public Object invoke(Object p, Method m, Object[] a) {
                if ("getUrl".equals(m.getName())) return url;
                if ("getResponse".equals(m.getName())) return response;
                return def(m.getReturnType());
            }
        });
        return mock(IInterceptedProxyMessage.class, new InvocationHandler() {
            @Override public Object invoke(Object p, Method m, Object[] a) {
                return "getMessageInfo".equals(m.getName()) ? rr : def(m.getReturnType());
            }
        });
    }

    public static void main(String[] args) throws Exception {
        testScope();
        testCrypto();
        testScanner();
        testExporter();
        testExtender();
        System.out.println();
        if (failed == 0) System.out.println("EDGE CASE TEST PASSED");
        else { System.out.println(failed + " EDGE CASE TEST(S) FAILED"); System.exit(1); }
    }
}
