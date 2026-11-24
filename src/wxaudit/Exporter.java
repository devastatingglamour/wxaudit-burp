package wxaudit;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/** JSON / HTML report writer. No third-party dependencies. */
public final class Exporter {

    private Exporter() { }

    public static void writeJson(File file, List<Scanner.Finding> findings, String target, int[] stats)
            throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"generated_at\": \"").append(isoNow()).append("\",\n");
        sb.append("  \"target\": ").append(q(target)).append(",\n");
        sb.append("  \"scanned\": ").append(stats[0]).append(",\n");
        sb.append("  \"skipped\": ").append(stats[1]).append(",\n");
        sb.append("  \"finding_count\": ").append(findings.size()).append(",\n");
        sb.append("  \"severity_counts\": {\"high\":").append(stats[3])
                .append(",\"medium\":").append(stats[4])
                .append(",\"low\":").append(stats[5])
                .append(",\"info\":").append(stats[6]).append("},\n");
        sb.append("  \"findings\": [\n");
        for (int i = 0; i < findings.size(); i++) {
            Scanner.Finding f = findings.get(i);
            sb.append("    {\"rule\":").append(q(f.rule))
                    .append(",\"name\":").append(q(f.name))
                    .append(",\"severity\":").append(q(f.severity))
                    .append(",\"group\":").append(q(f.group))
                    .append(",\"value\":").append(q(f.value))
                    .append(",\"file\":").append(q(f.file))
                    .append(",\"line\":").append(f.line)
                    .append(",\"snippet\":").append(q(f.snippet))
                    .append(",\"note\":").append(q(f.note))
                    .append(",\"source_url\":").append(q(f.sourceUrl))
                    .append("}").append(i + 1 < findings.size() ? "," : "").append("\n");
        }
        sb.append("  ]\n}\n");
        write(file, sb.toString());
    }

    public static void writeHtml(File file, List<Scanner.Finding> findings, String target, int[] stats)
            throws Exception {
        StringBuilder rows = new StringBuilder();
        for (Scanner.Finding f : findings) {
            String color = color(f.severity);
            rows.append("<tr><td><span class='sev' style='background:").append(color).append("'>")
                    .append(label(f.severity)).append("</span></td><td>").append(esc(f.name))
                    .append("</td><td class='val'>").append(esc(f.value))
                    .append("</td><td class='loc'>").append(esc(f.file)).append(":").append(f.line)
                    .append("</td><td class='src'>").append(esc(f.sourceUrl))
                    .append("</td><td class='snip'>").append(esc(f.snippet)).append("</td></tr>\n");
        }
        String doc = "<!doctype html>\n<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
                + "<title>wxaudit 报告</title><style>\n"
                + ":root{--bg:#f8f9fa;--card:#fff;--line:#dadce0;--text:#202124;--muted:#5f6368}\n"
                + "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);"
                + "font:14px/1.55 -apple-system,BlinkMacSystemFont,\"Segoe UI\",\"Microsoft YaHei\",sans-serif}\n"
                + ".wrap{max-width:1400px;margin:28px auto;padding:0 20px}h1{font-size:23px;margin:0 0 4px}\n"
                + ".meta{color:var(--muted);font-size:12px;margin-bottom:18px}\n"
                + ".cards{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:16px}\n"
                + ".card{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:12px}\n"
                + ".card b{display:block;font-size:24px}.card span{color:var(--muted);font-size:12px}\n"
                + "table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:9px;overflow:hidden}\n"
                + "th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}\n"
                + "th{background:#f1f3f4;font-size:12px;color:var(--muted)}tr:last-child td{border-bottom:0}\n"
                + ".sev{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;white-space:nowrap}\n"
                + ".val{font-family:Consolas,monospace;word-break:break-all;max-width:330px}\n"
                + ".loc,.src,.snip{color:var(--muted);font-family:Consolas,monospace;word-break:break-all}\n"
                + ".loc{max-width:220px}.src{max-width:240px}.snip{max-width:300px}\n"
                + ".note{background:#fff8e1;border:1px solid #ffe082;border-radius:8px;padding:10px;font-size:12px;margin-bottom:16px}\n"
                + "</style></head><body><div class=\"wrap\">\n"
                + "<h1>wxaudit · 被动扫描报告</h1>\n"
                + "<div class=\"meta\">目标：" + esc(target) + " &nbsp;|&nbsp; 生成：" + isoNow() + "</div>\n"
                + "<div class=\"cards\">"
                + card(stats[0], "已扫描", "#202124") + card(stats[1], "已跳过", "#5f6368")
                + card(stats[3], "高危", "#d93025") + card(stats[4], "中危", "#e37400")
                + card(stats[5], "低危", "#1a73e8") + card(stats[6], "提示", "#5f6368")
                + "</div>\n"
                + "<div class=\"note\">仅列出静态匹配结果，需人工复核；密钥类发现请确认有效性后按正规流程上报。</div>\n"
                + "<table><thead><tr><th>等级</th><th>规则</th><th>命中值</th><th>位置</th><th>来源 URL</th><th>上下文</th></tr></thead><tbody>\n"
                + (rows.length() == 0 ? "<tr><td colspan='6'>无发现</td></tr>" : rows.toString())
                + "</tbody></table></div></body></html>\n";
        write(file, doc);
    }

    private static String card(int n, String label, String color) {
        return "<div class=\"card\"><b style=\"color:" + color + "\">" + n + "</b><span>" + label + "</span></div>";
    }

    private static String color(String sev) {
        if ("high".equals(sev)) return "#d93025";
        if ("medium".equals(sev)) return "#e37400";
        if ("low".equals(sev)) return "#1a73e8";
        return "#5f6368";
    }

    private static String label(String sev) {
        if ("high".equals(sev)) return "高危";
        if ("medium".equals(sev)) return "中危";
        if ("low".equals(sev)) return "低危";
        return "提示";
    }

    private static String isoNow() {
        return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date());
    }

    private static String q(String s) {
        if (s == null) return "\"\"";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static void write(File file, String content) throws Exception {
        File parent = file.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();
        Writer w = new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8);
        try { w.write(content); } finally { w.close(); }
    }
}
