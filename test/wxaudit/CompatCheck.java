package wxaudit;

import java.lang.reflect.Method;

/**
 * Runs on Burp's bundled JRE against the real burpsuite_pro_org.jar.
 * Verifies every stub signature we compiled against actually exists in the
 * real Burp API, so the extension class loads and links correctly.
 */
public class CompatCheck {

    static int failed = 0;

    static void check(boolean ok, String label) {
        System.out.println((ok ? "  OK   " : "  FAIL ") + label);
        if (!ok) failed++;
    }

    static void method(String iface, String name, Class<?>... params) throws Exception {
        try {
            Method m = Class.forName(iface).getMethod(name, params);
            check(true, iface + "." + name + " -> " + m.getReturnType().getSimpleName());
        } catch (NoSuchMethodException ex) {
            check(false, iface + "." + name + " MISSING (stub signature mismatch!)");
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Burp API compatibility check (real jar on Burp JRE)");
        Class<?> ext = Class.forName("wxaudit.BurpExtender");
        check(Class.forName("burp.IBurpExtender").isAssignableFrom(ext), "BurpExtender implements IBurpExtender");
        check(Class.forName("burp.IProxyListener").isAssignableFrom(ext), "BurpExtender implements IProxyListener");
        check(Class.forName("burp.ITab").isAssignableFrom(ext), "BurpExtender implements ITab");

        method("burp.IBurpExtender", "registerExtenderCallbacks", Class.forName("burp.IBurpExtenderCallbacks"));
        method("burp.IProxyListener", "processProxyMessage", boolean.class, Class.forName("burp.IInterceptedProxyMessage"));
        method("burp.ITab", "getTabCaption");
        method("burp.ITab", "getUiComponent");

        String cb = "burp.IBurpExtenderCallbacks";
        method(cb, "setExtensionName", String.class);
        method(cb, "getHelpers");
        method(cb, "printOutput", String.class);
        method(cb, "printError", String.class);
        method(cb, "registerProxyListener", Class.forName("burp.IProxyListener"));
        method(cb, "addSuiteTab", Class.forName("burp.ITab"));
        method(cb, "loadExtensionSetting", String.class);
        method(cb, "saveExtensionSetting", String.class, String.class);

        method("burp.IExtensionHelpers", "analyzeResponse", byte[].class);
        method("burp.IResponseInfo", "getBodyOffset");
        method("burp.IInterceptedProxyMessage", "getMessageInfo");
        method("burp.IHttpRequestResponse", "getRequest");
        method("burp.IHttpRequestResponse", "getResponse");
        method("burp.IHttpRequestResponse", "getUrl");

        // Actually instantiate: forces verification of implemented interface methods.
        Object instance = ext.newInstance();
        check(instance != null, "BurpExtender instantiates with real API classes");

        System.out.println();
        if (failed == 0) System.out.println("BURP API COMPATIBILITY OK");
        else { System.out.println(failed + " INCOMPATIBILITY(IES) FOUND"); System.exit(1); }
    }
}
