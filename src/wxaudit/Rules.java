package wxaudit;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Detection rules ported from the verified Python implementation. */
public final class Rules {

    public static final class Rule {
        public final String id;
        public final String name;
        public final String severity;
        public final String group;
        public final Pattern pattern;
        public final int capture;
        public final String note;

        public Rule(String id, String name, String severity, String group,
                    String regex, int capture, String note, boolean ignoreCase) {
            this.id = id;
            this.name = name;
            this.severity = severity;
            this.group = group;
            this.pattern = Pattern.compile(regex, ignoreCase ? Pattern.CASE_INSENSITIVE : 0);
            this.capture = capture;
            this.note = note == null ? "" : note;
        }
    }

    public static final List<Rule> ALL = build();

    private static List<Rule> build() {
        List<Rule> r = new ArrayList<Rule>();
        r.add(new Rule("cloud_ak", "云厂商 AccessKey ID", "high", "secret",
                "\\b(?:AKID[A-Za-z0-9]{12,}|LTAI[A-Za-z0-9]{12,}|AKIA[A-Z0-9]{16}|QAK[A-Za-z0-9]{12,})\\b",
                0, "阿里云 / 腾讯云 / AWS 等长期密钥，泄露可直接接管云资源", false));
        r.add(new Rule("secret_assign", "疑似硬编码密钥/Token", "high", "secret",
                "\\b(?:appsecret|app_secret|secretkey|secret_key|accesskey|access_key|api[_-]?key|private[_-]?key|password|passwd|pwd|secret)\\b\\s*[:=]\\s*[\"']([^\"']{6,160})[\"']",
                1, "硬编码在前端的配置，需人工确认是否为有效凭据", true));
        r.add(new Rule("jwt_token", "JWT 令牌", "medium", "secret",
                "\\beyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b",
                0, "前端出现完整 JWT，可能存在会话泄露或长期使用问题", false));
        r.add(new Rule("private_key", "私钥材料", "high", "secret",
                "-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
                0, "出现私钥头，检查是否被打入前端包", false));
        r.add(new Rule("wx_sessionkey", "session_key 相关字段", "medium", "secret",
                "session_?key\\s*[:=]\\s*[\"']([^\"']{8,120})[\"']",
                1, "session_key 泄露可结合 iv 加解密开放数据，导致任意用户登录", true));
        r.add(new Rule("id_card", "身份证号", "medium", "pii",
                "(?<![0-9])[1-9][0-9]{5}(?:18|19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx](?![0-9])",
                0, "可能来自测试数据或接口响应样例", false));
        r.add(new Rule("phone", "手机号", "low", "pii",
                "(?<!\\d)1[3-9]\\d{9}(?!\\d)", 0, "", false));
        r.add(new Rule("email", "邮箱地址", "low", "pii",
                "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", 0, "", false));
        r.add(new Rule("internal_ip", "内网 IP / IP:端口", "info", "pii",
                "(?:(?:10|127)\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3})(?::\\d{1,5})?",
                0, "内网地址与端口，辅助判断后端资产结构", false));
        r.add(new Rule("abs_url", "绝对 URL", "info", "endpoint",
                "https?://[^\\s\"'<>`\\\\,;)\\}\\]]{4,200}",
                0, "含 API 网关、测试环境、第三方服务地址", false));
        r.add(new Rule("base_url", "API BaseURL 配置", "medium", "endpoint",
                "\\b(?:baseurl|apiurl|api_base|apibase|serverhost|hosturl)\\b\\s*[:=]\\s*[\"'](https?://[^\"']{4,200})[\"']",
                1, "", true));
        r.add(new Rule("api_path", "可疑 API 路径", "info", "endpoint",
                "[\"'`](\\/(?:api|v\\d+|gateway|prod|test|dev|admin|internal|open|service)[A-Za-z0-9_\\-./\\{\\}$?=&%]{2,160})[\"'`]",
                1, "", false));
        r.add(new Rule("wx_request", "wx.request 目标", "info", "endpoint",
                "wx\\.(?:request|uploadFile|downloadFile)\\s*\\(\\s*\\{[\\s\\S]{0,400}?url\\s*:\\s*[\"']([^\"']{2,200})[\"']",
                1, "", false));
        r.add(new Rule("func_call_path", "请求函数调用路径", "info", "endpoint",
                "\\b(?:request|fetch|axios)\\s*\\(\\s*[\"'`](\\/[^\"'`]{2,160})[\"'`]",
                1, "", false));
        return r;
    }

    private static final List<String> IGNORE_URL_SUBSTR = Arrays.asList(
            "weixin.qq.com", "qq.com/", "w3.org", "schema.org", "example.com",
            "github.com", "npmjs.com", "babeljs.io", "mozilla.org", "localhost");
    private static final List<String> IGNORE_PATH_PREFIX = Arrays.asList(
            "/pages/", "/components/", "/images/", "/static/", "/assets/",
            "/res/", "/node_modules/", "/miniprogram_npm/");
    private static final Set<String> IGNORE_VALUES = new HashSet<String>(Arrays.asList(
            "true", "false", "null", "undefined", "none", "0", "1", "yes", "no", "-", "*"));

    public static boolean isIgnored(String ruleId, String value) {
        String v = value == null ? "" : value.trim();
        if (IGNORE_VALUES.contains(v.toLowerCase(Locale.ROOT))) return true;
        String low = v.toLowerCase(Locale.ROOT);
        if ("abs_url".equals(ruleId)) {
            for (String s : IGNORE_URL_SUBSTR) if (low.contains(s)) return true;
        }
        if ("api_path".equals(ruleId) || "func_call_path".equals(ruleId) || "wx_request".equals(ruleId)) {
            for (String p : IGNORE_PATH_PREFIX) if (v.startsWith(p)) return true;
        }
        return false;
    }

    public static int severityRank(String sev) {
        if ("high".equals(sev)) return 0;
        if ("medium".equals(sev)) return 1;
        if ("low".equals(sev)) return 2;
        return 3;
    }

    private Rules() { }
}
