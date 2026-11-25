package wxaudit;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IInterceptedProxyMessage;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.ITab;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Round-3 verification: load BurpExtender from the delivered JAR on Burp's
 * own JRE21 with the real burp API jar, then drive a mocked proxy response.
 * Run with classpath = real burpsuite_pro_org.jar + wxaudit-burp.jar + test-out.
 */
public class JarLoadTest {

    static int failed = 0;

    static void check(boolean ok, String label) {
        System.out.println((ok ? "  OK   " : "  FAIL ") + label);
        if (!ok) failed++;
    }

    @SuppressWarnings("unchecked")
    static <T> T mock(Class<T> iface, InvocationHandler h) {
        return (T) Proxy.newProxyInstance(JarLoadTest.class.getClassLoader(), new Class<?>[]{iface}, h);
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

    public static void main(String[] args) throws Exception {
        System.out.println("Round 3: load from delivered JAR on Burp JRE with real API jar");

        Class<?> clazz = Class.forName("wxaudit.BurpExtender");
        String origin = String.valueOf(clazz.getProtectionDomain().getCodeSource().getLocation());
        check(origin.contains("wxaudit-burp.jar"), "BurpExtender loaded from jar: " + origin);

        // AI enhancement classes must load from the delivered jar on Burp JRE21.
        String[] aiClasses = { "wxaudit.Json", "wxaudit.AiConfig", "wxaudit.LlmClient",
                "wxaudit.AiAnalyzer", "wxaudit.CapturedPacket", "wxaudit.RouteFinding",
                "wxaudit.AiResultStore", "wxaudit.AiPrompts" };
        for (String cn : aiClasses) {
            try {
                Class<?> c = Class.forName(cn);
                check(c.getProtectionDomain().getCodeSource().getLocation().toString().contains("wxaudit-burp.jar"),
                        "AI class loaded from jar: " + cn);
            } catch (Throwable t) {
                check(false, "AI class load failed: " + cn + " -> " + t);
            }
        }
        // Default AI config must be disabled (zero external requests).
        try {
            Class<?> ac = Class.forName("wxaudit.AiConfig");
            Object def = ac.getMethod("defaults").invoke(null);
            check(Boolean.FALSE.equals(ac.getMethod("isNetworkAllowed").invoke(def)),
                    "default AiConfig is network-disabled");
        } catch (Throwable t) {
            check(false, "AiConfig defaults check failed: " + t);
        }

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

        Map<String, String> settings = new HashMap<String, String>();
        settings.put("wxaudit.scope", "target-corp.cn");
        settings.put("wxaudit.wxid", "wx1234567890abcdef");
        final Map<String, String> cfg = settings;
        IBurpExtenderCallbacks cb = mock(IBurpExtenderCallbacks.class, new InvocationHandler() {
            @Override public Object invoke(Object p, Method m, Object[] a) {
                String name = m.getName();
                if ("getHelpers".equals(name)) return helpers;
                if ("loadExtensionSetting".equals(name)) return cfg.get(a[0]);
                return def(m.getReturnType());
            }
        });

        Object ext = clazz.newInstance();
        Method register = clazz.getMethod("registerExtenderCallbacks", IBurpExtenderCallbacks.class);
        register.invoke(ext, cb);

        ITab tab = (ITab) ext;
        check("wxaudit".equals(tab.getTabCaption()), "ITab caption = wxaudit");
        check(tab.getUiComponent() != null, "ITab UI component created after registration");

        Field uniqueField = clazz.getDeclaredField("unique");
        uniqueField.setAccessible(true);
        ConcurrentHashMap<?, ?> unique = (ConcurrentHashMap<?, ?>) uniqueField.get(ext);

        String head = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n";
        byte[] body = ("var BASE='https://api.target-corp.cn/v2';var ak='LTAI5tABCDEFGHIJKLMNOP';"
                + "wx.request({url:'/api/v1/user'});").getBytes(StandardCharsets.UTF_8);
        byte[] raw = new byte[head.length() + body.length];
        System.arraycopy(head.getBytes(StandardCharsets.ISO_8859_1), 0, raw, 0, head.length());
        System.arraycopy(body, 0, raw, head.length(), body.length);

        final IHttpRequestResponse rr = mock(IHttpRequestResponse.class, new InvocationHandler() {
            @Override public Object invoke(Object p, Method m, Object[] a) {
                if ("getUrl".equals(m.getName())) {
                    try { return new URL("https://cdn.target-corp.cn/app.js"); }
                    catch (Exception ex) { return null; }
                }
                if ("getResponse".equals(m.getName())) return raw;
                return def(m.getReturnType());
            }
        });
        IInterceptedProxyMessage msg = mock(IInterceptedProxyMessage.class, new InvocationHandler() {
            @Override public Object invoke(Object p, Method m, Object[] a) {
                return "getMessageInfo".equals(m.getName()) ? rr : def(m.getReturnType());
            }
        });

        Method process = clazz.getMethod("processProxyMessage", boolean.class, IInterceptedProxyMessage.class);
        process.invoke(ext, false, msg);
        check(unique.size() > 0, "mocked proxy response scanned from jar (" + unique.size() + " findings)");

        System.out.println();
        if (failed == 0) System.out.println("JAR LOAD TEST PASSED");
        else { System.out.println(failed + " JAR LOAD TEST(S) FAILED"); System.exit(1); }
    }
}
