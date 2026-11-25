package wxaudit;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 捕获的数据包旁路结构 / Captured packet side-car structure.
 *
 * <p>不落盘、只存内存。为 AI 完整利用链分析提供请求方法、参数名、响应摘要、
 * 关联 Finding 键与路由。所有敏感值在构造前已脱敏。
 * In-memory only, never persisted. Provides method, parameters, response excerpt,
 * linked finding keys and routes for full exploit-chain analysis. Values are redacted.
 */
public final class CapturedPacket {
    public final String id;                 // sourceUrl + \u0001 + method + \u0001 + timestamp
    public final String sourceUrl;
    public final String method;
    public final String kind;               // "JS/文本" | "wxapkg(明文)" | "wxapkg(加密)"
    public final long timestamp;
    public final String requestHead;        // 请求行 + 参数名，已脱敏，≤1000 字符
    public final String responseExcerpt;    // 响应体摘要，已脱敏，≤2000 字符
    public final List<String> findingKeys;  // 指向 unique 的 Finding.key()
    public final List<RouteFinding> routes;

    public CapturedPacket(String sourceUrl, String method, String kind, long timestamp,
                          String requestHead, String responseExcerpt,
                          List<String> findingKeys, List<RouteFinding> routes) {
        this.sourceUrl = sourceUrl == null ? "" : sourceUrl;
        this.method = method == null ? "" : method;
        this.kind = kind == null ? "" : kind;
        this.timestamp = timestamp;
        this.requestHead = cut(requestHead, 1000);
        this.responseExcerpt = cut(responseExcerpt, 2000);
        this.findingKeys = findingKeys == null
                ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new ArrayList<String>(findingKeys));
        this.routes = routes == null
                ? Collections.<RouteFinding>emptyList()
                : Collections.unmodifiableList(new ArrayList<RouteFinding>(routes));
        this.id = this.sourceUrl + "\u0001" + this.method + "\u0001" + this.timestamp;
    }

    /** 生成数据包 id（供 UI 选择与结果关联）。 */
    public static String makeId(String sourceUrl, String method, long timestamp) {
        return (sourceUrl == null ? "" : sourceUrl) + "\u0001"
                + (method == null ? "" : method) + "\u0001" + timestamp;
    }

    private static String cut(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "\u2026";
    }
}
