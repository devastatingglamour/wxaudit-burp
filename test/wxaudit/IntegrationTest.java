package wxaudit;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IInterceptedProxyMessage;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** End-to-end check of the passive-scan chain using mocked Burp callbacks. */
public class IntegrationTest {

    static int failed = 0;

    static void check(boolean ok, String label) {
        System.out.println((ok ? "  OK   " : "  FAIL ") + label);
        if (!ok) failed++;
    }

    @SuppressWarnings("unchecked")
    static <T> T mock(Class<T> iface, InvocationHandler h) {
        return (T) Proxy.newProxyInstance(IntegrationTest.class.getClassLoader(), new Class<?>[]{iface}, h);
    }

    static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == short.class) return (short) 0;
        if (type == byte.class) return (byte) 0;
        if (type == long.class) return 0L;
        return null;
    }

    static byte[] httpResponse(String contentType, byte[] body) {
        String head = "HTTP/1.1 200 OK\r\nContent-Type: " + contentType
                + "\r\nContent-Length: " + body.length + "\r\n\r\n";
        byte[] h = head.getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = new byte[h.length + body.length];
        System.arraycopy(h, 0, out, 0, h.length);
        System.arraycopy(body, 0, out, h.length, body.length);
        return out;
    }

    static IInterceptedProxyMessage message(final URL url, final byte[] response) {
        final IHttpRequestResponse rr = mock(IHttpRequestResponse.class, new InvocationHandler() {
            @Override public Object invoke(Object p, Method m, Object[] a) {
                if ("getUrl".equals(m.getName())) return url;
                if ("getResponse".equals(m.getName())) return response;
                if ("getRequest".equals(m.getName())) return new byte[0];
                return defaultValue(m.getReturnType());
            }
        });
        return mock(IInterceptedProxyMessage.class, new InvocationHandler() {
            @Override public Object invoke(Object p, Method m, Object[] a) {
                if ("getMessageInfo".equals(m.getName())) return rr;
                return defaultValue(m.getReturnType());
            }
        });
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        System.out.println("End-to-end passive scan with mocked Burp callbacks");
        final Map<String, String> settings = new HashMap<String, String>();
        settings.put("wxaudit.scope", "target-corp.cn");

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
                    final int bodyOffset = off;
                    return mock(IResponseInfo.class, new InvocationHandler() {
                        @Override public Object invoke(Object p2, Method m2, Object[] a2) {
                            if ("getBodyOffset".equals(m2.getName())) return bodyOffset;
                            return defaultValue(m2.getReturnType());
                        }
                    });
                }
                return defaultValue(m.getReturnType());
            }
        });

        IBurpExtenderCallbacks cb = mock(IBurpExtenderCallbacks.class, new InvocationHandler() {
            @Override public Object invoke(Object p, Method m, Object[] a) {
                String name = m.getName();
                if ("getHelpers".equals(name)) return helpers;
                if ("loadExtensionSetting".equals(name)) return settings.get((String) a[0]);
                return defaultValue(m.getReturnType());
            }
        });

        BurpExtender ext = new BurpExtender();
        ext.registerExtenderCallbacks(cb);

        Field scopeField = BurpExtender.class.getDeclaredField("scope");
        scopeField.setAccessible(true);
        check(((ScopeFilter) scopeField.get(ext)).isConfigured(), "target scope restored from settings");

        Field uniqueField = BurpExtender.class.getDeclaredField("unique");
        uniqueField.setAccessible(true);
        ConcurrentHashMap<?, ?> unique = (ConcurrentHashMap<?, ?>) uniqueField.get(ext);
        Field skippedField = BurpExtender.class.getDeclaredField("skippedCount");
        skippedField.setAccessible(true);
        AtomicInteger skipped = (AtomicInteger) skippedField.get(ext);

        String js = "var BASE='https://api.target-corp.cn/v2';var ak='LTAI5tABCDEFGHIJKLMNOP';"
                + "wx.request({url:'/api/v1/user',method:'POST'});";
        byte[] jsResp = httpResponse("application/javascript", js.getBytes(StandardCharsets.UTF_8));

        int before = unique.size();
        ext.processProxyMessage(false, message(new URL("https://cdn.target-corp.cn/app.js"), jsResp));
        int afterInScope = unique.size();
        check(afterInScope > before, "in-scope JS response produced findings (" + (afterInScope - before) + ")");

        ext.processProxyMessage(false, message(new URL("https://evil.com/app.js"), jsResp));
        check(unique.size() == afterInScope, "out-of-scope response produced no findings");
        check(skipped.get() >= 1, "out-of-scope response counted as skipped");

        // wxapkg response in scope
        List<Wxapkg.VirtualFile> files = new ArrayList<Wxapkg.VirtualFile>();
        files.add(new Wxapkg.VirtualFile("app-config.json",
                "{\"appid\":\"wx1234567890abcdef\",\"page\":{\"pages/admin/panel\":{}}}"
                        .getBytes(StandardCharsets.UTF_8)));
        files.add(new Wxapkg.VirtualFile("app-service.js",
                "var SECRET='abc123secretkey987654';var phone='13812345678';"
                        .getBytes(StandardCharsets.UTF_8)));
        byte[] pkg = Wxapkg.buildPlainPackage(files);
        byte[] pkgResp = httpResponse("application/octet-stream", pkg);
        int beforePkg = unique.size();
        ext.processProxyMessage(false, message(new URL("https://api.target-corp.cn/app.wxapkg"), pkgResp));
        check(unique.size() > beforePkg, "in-scope wxapkg response unpacked and scanned");

        System.out.println();
        if (failed == 0) System.out.println("INTEGRATION TEST PASSED");
        else { System.out.println(failed + " INTEGRATION TEST(S) FAILED"); System.exit(1); }
    }
}
