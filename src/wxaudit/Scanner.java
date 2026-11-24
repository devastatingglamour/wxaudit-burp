package wxaudit;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;

/** Static text scanner: secrets, PII and endpoint clues. */
public final class Scanner {

    public static final class Finding {
        public final String rule;
        public final String name;
        public final String severity;
        public final String group;
        public final String value;
        public final String file;
        public final int line;
        public final String snippet;
        public final String note;
        public final String sourceUrl;
        public final long timestamp;

        public Finding(String rule, String name, String severity, String group, String value,
                       String file, int line, String snippet, String note, String sourceUrl) {
            this.rule = rule; this.name = name; this.severity = severity; this.group = group;
            this.value = value; this.file = file; this.line = line; this.snippet = snippet;
            this.note = note; this.sourceUrl = sourceUrl;
            this.timestamp = System.currentTimeMillis();
        }

        public String key() {
            return rule + "\u0001" + value + "\u0001" + file + "\u0001" + line + "\u0001" + sourceUrl;
        }
    }

    public static final List<String> SCAN_EXT = java.util.Arrays.asList(
            ".js", ".json", ".html", ".htm", ".xml", ".txt", ".wxml", ".wxss", ".wxs", ".map");
    public static final int MAX_SCAN_BYTES = 8 * 1024 * 1024;
    private static final java.util.regex.Pattern SUSPICIOUS_ROUTE = java.util.regex.Pattern.compile(
            "admin|test|debug|internal|dev|manage|config|secret|backup|demo|stg|uat",
            java.util.regex.Pattern.CASE_INSENSITIVE);

    private Scanner() { }

    public static boolean isScannableName(String name) {
        if (name == null) return false;
        String n = name.toLowerCase(Locale.ROOT);
        int q = n.indexOf('?');
        if (q > 0) n = n.substring(0, q);
        for (String ext : SCAN_EXT) if (n.endsWith(ext)) return true;
        return false;
    }

    /** Scan a single text blob. Returns findings sorted by severity. */
    public static List<Finding> scanText(String text, String fileLabel, String sourceUrl) {
        List<Finding> out = new ArrayList<Finding>();
        if (text == null || text.isEmpty()) return out;
        String[] lines = text.split("\\r?\\n", -1);
        for (Rules.Rule rule : Rules.ALL) {
            Matcher m = rule.pattern.matcher(text);
            int guard = 0;
            while (m.find() && guard++ < 5000) {
                String value;
                try { value = m.group(rule.capture); }
                catch (Exception ex) { value = m.group(0); }
                if (value == null) value = m.group(0);
                if (value.isEmpty() || Rules.isIgnored(rule.id, value)) continue;
                value = value.trim();
                if (value.length() > 300) value = value.substring(0, 300) + "\u2026";
                int line = lineNumber(text, m.start());
                String snippet = (line > 0 && line <= lines.length) ? lines[line - 1].trim() : "";
                if (snippet.length() > 240) snippet = snippet.substring(0, 240);
                out.add(new Finding(rule.id, rule.name, rule.severity, rule.group,
                        value, fileLabel, line, snippet, rule.note, sourceUrl));
            }
        }
        // de-duplicate identical matches within this blob (important for JS responses,
        // which are scanned directly without the cross-file dedupe step)
        Set<String> seen = new HashSet<String>();
        List<Finding> unique = new ArrayList<Finding>();
        for (Finding f : out) {
            String key = f.rule + "\u0001" + f.value + "\u0001" + f.line;
            if (seen.add(key)) unique.add(f);
        }
        Collections.sort(unique, new Comparator<Finding>() {
            @Override public int compare(Finding a, Finding b) {
                int d = Rules.severityRank(a.severity) - Rules.severityRank(b.severity);
                if (d != 0) return d;
                if (!a.file.equals(b.file)) return a.file.compareTo(b.file);
                return a.line - b.line;
            }
        });
        return unique;
    }

    /** Scan all text-like files from an unpacked wxapkg. */
    public static List<Finding> scanPackageFiles(List<Wxapkg.VirtualFile> files, String sourceUrl) {
        List<Finding> out = new ArrayList<Finding>();
        if (files == null) return out;
        for (Wxapkg.VirtualFile vf : files) {
            if (vf == null || vf.data == null) continue;
            if (!isScannableName(vf.name)) continue;
            if (vf.data.length > MAX_SCAN_BYTES) continue;
            String text = new String(vf.data, StandardCharsets.UTF_8);
            out.addAll(scanText(text, vf.name, sourceUrl));
        }
        return dedupe(out);
    }

    public static List<Finding> dedupe(List<Finding> in) {
        Set<String> seen = new HashSet<String>();
        List<Finding> out = new ArrayList<Finding>();
        for (Finding f : in) if (seen.add(f.key())) out.add(f);
        Collections.sort(out, new Comparator<Finding>() {
            @Override public int compare(Finding a, Finding b) {
                return Rules.severityRank(a.severity) - Rules.severityRank(b.severity);
            }
        });
        return out;
    }

    public static List<String> extractRoutes(List<Wxapkg.VirtualFile> files) {
        List<String> routes = new ArrayList<String>();
        for (Wxapkg.VirtualFile vf : files) {
            if (!vf.name.endsWith("app-config.json")) continue;
            String text = new String(vf.data, StandardCharsets.UTF_8);
            // lightweight scan of "page":{"<route>":{...}}
            int p = text.indexOf("\"page\"");
            if (p < 0) continue;
            Matcher m = java.util.regex.Pattern.compile("\"(pages/[^\"]+)\"\\s*:\\s*\\{")
                    .matcher(text.substring(p));
            while (m.find()) {
                String route = m.group(1);
                if (SUSPICIOUS_ROUTE.matcher(route).find()) routes.add(route);
            }
        }
        return routes;
    }

    private static int lineNumber(String text, int offset) {
        int n = 1;
        for (int i = 0; i < offset; i++) if (text.charAt(i) == '\n') n++;
        return n;
    }
}
