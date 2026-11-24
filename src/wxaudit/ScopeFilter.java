package wxaudit;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Target scope filter. Only responses whose request URL matches one of the
 * configured entries are scanned. This keeps the result set focused on a
 * single engagement even when Burp captures traffic from many hosts.
 *
 * Entry syntax (one per line, comma/semicolon separated, '#' comments):
 *   example.com                 -> example.com and all subdomains
 *   *.example.com               -> subdomains only (not the apex domain)
 *   https://example.com/api/v1  -> exact host + path prefix
 *   example.com/api/v1          -> same as above (scheme optional)
 */
public final class ScopeFilter {

    public static final class Entry {
        public final String raw;
        public final String host;
        public final String pathPrefix;
        public final boolean subdomains;
        public final boolean includeApex;

        Entry(String raw, String host, String pathPrefix, boolean subdomains, boolean includeApex) {
            this.raw = raw;
            this.host = host;
            this.pathPrefix = pathPrefix;
            this.subdomains = subdomains;
            this.includeApex = includeApex;
        }

        public boolean matches(String reqHost, String reqPath) {
            String h = reqHost == null ? "" : reqHost.toLowerCase(Locale.ROOT);
            String target = host.toLowerCase(Locale.ROOT);
            boolean exact = h.equals(target);
            boolean hostOk = (exact && includeApex) || (subdomains && h.endsWith("." + target));
            if (!hostOk) return false;
            if (pathPrefix == null || pathPrefix.isEmpty()) return true;
            String p = reqPath == null ? "" : reqPath;
            return p.equals(pathPrefix) || p.startsWith(pathPrefix.endsWith("/") ? pathPrefix : pathPrefix + "/");
        }

        @Override public String toString() { return raw; }
    }

    private volatile List<Entry> current = Collections.emptyList();

    /** Returns true when at least one target entry is configured. */
    public boolean isConfigured() { return !current.isEmpty(); }

    public List<Entry> entries() { return current; }

    /** Parse and atomically replace the target list. */
    public void configure(String text) {
        List<Entry> parsed = new ArrayList<Entry>();
        if (text != null) {
            String[] lines = text.split("[\\r\\n,;]+");
            for (String line : lines) {
                String s = line.trim();
                if (s.isEmpty() || s.startsWith("#") || s.startsWith("//")) continue;
                Entry e = parseEntry(s);
                if (e != null) parsed.add(e);
            }
        }
        current = Collections.unmodifiableList(parsed);
    }

    private static Entry parseEntry(String raw) {
        try {
            String s = raw;
            boolean subdomains = true;
            boolean includeApex = true;
            if (s.startsWith("*.")) {
                subdomains = true;
                includeApex = false;
                s = s.substring(2);
            }
            String pathPrefix = null;
            String host;
            if (s.startsWith("http://") || s.startsWith("https://")) {
                URL u = new URL(s);
                host = u.getHost();
                String p = u.getPath();
                if (p != null && !p.isEmpty() && !"/".equals(p)) pathPrefix = p;
                subdomains = false;
                includeApex = true;
            } else if (s.indexOf('/') > 0) {
                URL u = new URL("http://" + s);
                host = u.getHost();
                String p = u.getPath();
                if (p != null && !p.isEmpty() && !"/".equals(p)) pathPrefix = p;
                subdomains = false;
                includeApex = true;
            } else {
                // host or host:port
                host = s;
                int colon = s.lastIndexOf(':');
                if (colon > 0 && colon < s.length() - 1 && s.indexOf(']') < 0) {
                    try { Integer.parseInt(s.substring(colon + 1)); host = s.substring(0, colon); }
                    catch (NumberFormatException ignored) { }
                }
            }
            if (host == null || host.isEmpty()) return null;
            return new Entry(raw, host, pathPrefix, subdomains, includeApex);
        } catch (MalformedURLException ex) {
            return null;
        }
    }

    /** Test a full URL string. */
    public boolean matches(String urlString) {
        if (urlString == null || current.isEmpty()) return false;
        try {
            URL u = new URL(urlString);
            return matches(u);
        } catch (MalformedURLException ex) {
            return false;
        }
    }

    public boolean matches(URL url) {
        if (url == null || current.isEmpty()) return false;
        String host = url.getHost();
        String path = url.getPath();
        List<Entry> snapshot = current;
        for (Entry e : snapshot) {
            if (e.matches(host, path)) return true;
        }
        return false;
    }
}
