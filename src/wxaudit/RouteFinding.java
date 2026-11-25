package wxaudit;

/**
 * 带上下文的可疑路由 / Suspicious route with context.
 *
 * <p>升级自旧的裸字符串路由，补充 file/line/snippet/sourceUrl，便于 AI 分析。
 * Upgraded from the old bare-string route with file/line/snippet/sourceUrl for AI analysis.
 */
public final class RouteFinding {
    public final String route;
    public final String file;
    public final int line;
    public final String snippet;
    public final String sourceUrl;

    public RouteFinding(String route, String file, int line, String snippet, String sourceUrl) {
        this.route = route == null ? "" : route;
        this.file = file == null ? "" : file;
        this.line = line;
        this.snippet = snippet == null ? "" : snippet;
        this.sourceUrl = sourceUrl == null ? "" : sourceUrl;
    }

    /** 唯一键 / Unique key. */
    public String key() {
        return route + "\u0001" + file + "\u0001" + line + "\u0001" + sourceUrl;
    }

    @Override public String toString() { return route; }
}
