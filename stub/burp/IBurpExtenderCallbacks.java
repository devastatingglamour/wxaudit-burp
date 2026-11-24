package burp;
public interface IBurpExtenderCallbacks {
    void setExtensionName(String name);
    IExtensionHelpers getHelpers();
    void printOutput(String message);
    void printError(String message);
    void registerProxyListener(IProxyListener listener);
    void addSuiteTab(ITab tab);
    String loadExtensionSetting(String name);
    void saveExtensionSetting(String name, String value);
}
