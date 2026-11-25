# 文件索引 / File Index

> 每个条目先中文说明，再英文说明。/ Each entry gives Chinese first, then English.

## 源码 / Source (`src/wxaudit/`)

| 文件 / File | 说明 / Description |
|---|---|
| `BurpExtender.java` | **扩展入口**：注册代理监听器与自定义 Tab，按目标过滤响应，调度解密解包与扫描，维护去重结果和统计。<br>**Entry point**: registers the proxy listener and custom tab, filters responses by target scope, orchestrates decryption/unpacking/scanning, and keeps deduplicated results and counters. |
| `ScopeFilter.java` | **作用域过滤**：解析目标网址（精确 host、子域通配、路径前缀），判断请求 URL 是否命中。<br>**Scope filter**: parses target URLs (exact host, subdomain wildcard, path prefix) and decides whether a request URL is in scope. |
| `Crypto.java` | **解密层**：PBKDF2-HMAC-SHA1 派生密钥、AES-256-CBC/NoPadding 解密、尾部 XOR；含魔数与 gzip 识别。全部用 JDK 标准库。<br>**Crypto layer**: PBKDF2-HMAC-SHA1 key derivation, AES-256-CBC/NoPadding decryption, tail XOR; magic-byte and gzip detection. JDK standard library only. |
| `Wxapkg.java` | **解包器**：内存中解析 wxapkg 索引表，还原文件路径与内容，提取其中 appid；含测试用明文包构造器。<br>**Unpacker**: parses the wxapkg index table in memory, restores file paths and contents, extracts embedded appid; includes a plaintext package builder for tests. |
| `Rules.java` | **检测规则**：14 条正则（secret / pii / endpoint 三类）及降噪白名单，从 Python 版移植并用标准向量验证。<br>**Detection rules**: 14 regex rules in three groups (secret / pii / endpoint) plus noise filters, ported from the Python version and verified with standard vectors. |
| `Scanner.java` | **扫描引擎**：文本扫描、行号与上下文提取、结果去重排序、从 `app-config.json` 提取可疑路由。<br>**Scan engine**: text scanning, line numbers and snippets, result deduplication/sorting, and hidden-route extraction from `app-config.json`. |
| `UiPanel.java` | **Swing 面板**：目标配置、AppID 输入、结果表格、筛选、详情、日志、导出按钮；所有更新在 EDT 线程。<br>**Swing panel**: target config, AppID input, result table, filters, detail view, log, export buttons; all mutations run on the EDT. |
| `Exporter.java` | **报告导出**：手写 JSON 转义与自包含浅色主题 HTML 报告，零第三方依赖。<br>**Report export**: hand-written JSON escaping and self-contained light-theme HTML reports, no third-party deps. |

## 接口桩 / API stubs (`stub/burp/`)

> 仅用于编译（Burp 主 jar 是 Java 21 字节码，本机 javac 8 无法读取）。不打进交付 jar，运行时由 Burp 提供真实接口类。
> Compile-only (Burp's main jar is Java 21 bytecode, unreadable by local javac 8). Never shipped in the jar; Burp supplies the real interfaces at runtime.

`IBurpExtender.java`、`IBurpExtenderCallbacks.java`、`IExtensionHelpers.java`、`IResponseInfo.java`、`IProxyListener.java`、`IInterceptedProxyMessage.java`、`IHttpRequestResponse.java`、`ITab.java` — 均为最小签名桩，方法签名经真实 jar 校验。/ Minimal signature stubs, verified against the real jar.

## 测试 / Tests (`test/wxaudit/`)

| 文件 / File | 说明 / Description |
|---|---|
| `SelfTest.java` | 核心自测 25 项：作用域、明文/加密包往返、规则命中、路由。<br>25 core assertions: scope, plaintext/encrypted roundtrip, rule hits, routes. |
| `IntegrationTest.java` | 模拟 Burp 回调的端到端测试 5 项：目标内外流量分离、wxapkg 扫描。<br>5 E2E assertions with mocked Burp callbacks: in/out-of-scope separation, wxapkg scanning. |
| `EdgeCaseTest.java` | 边界与异常 49 项：畸形输入、路径前缀误匹配、去重、转义、超大响应、gzip、空参数。<br>49 boundary assertions: malformed input, path-prefix confusion, dedupe, escaping, oversized responses, gzip, null args. |
| `CompatCheck.java` | 在 Burp JRE21 上用真实 API jar 校验 22 个接口签名并可实例化。<br>22 API signature checks on Burp JRE21 against the real jar, plus instantiation. |
| `JarLoadTest.java` | 第三轮：从交付 jar 直接加载扩展并驱动模拟响应。<br>Round 3: load the extension from the delivered jar and drive a mocked response. |

## 脚本与文档 / Scripts & docs

| 文件 / File | 说明 / Description |
|---|---|
| `build.sh` | 编译、四类测试、API 兼容校验、打包。<br>Compile, run four test groups, check API compatibility, package the jar. |
| `verify.sh` | 三轮验收：全量构建、可复现性与产物完整性、真实 JRE 从 jar 加载。<br>Three acceptance rounds: full build, reproducibility/integrity, real-JRE load from jar. |
| `pack.py` | 以固定时间戳写 JAR(ZIP)，保证构建字节级可复现。<br>Writes the JAR (ZIP) with fixed timestamps for byte-for-byte reproducible builds. |
| `.github/workflows/ci.yml` | GitHub Actions 持续集成：编译、三组 mock 测试、可复现打包校验。<br>GitHub Actions CI: compile, three mocked test groups, reproducible packaging check. |
| `README.md` / `README.en.md` | 中文 / 英文使用说明。<br>Chinese / English usage guide. |
| `VERIFICATION.md` | 三轮验收报告与 SHA256。<br>Three-round verification report with SHA256. |
| `CHANGELOG.md` | 中英文更新日志。<br>Bilingual changelog. |
| `CONTRIBUTING.md` | 贡献与发布流程、版本规则、安全注意。<br>Contribution and release process, versioning, safety notes. |
| `SECURITY.md` | 安全策略：授权使用、数据处理、漏洞报告方式。<br>Security policy: authorized use, data handling, vulnerability reporting. |
| `LICENSE` | MIT 许可证（标准英文法律文本）。<br>MIT license (standard English legal text). |
| `RELEASE_NOTES.md` | 中英文发布说明与操作步骤。<br>Bilingual release notes and publishing steps. |
| `release.py` | 一键发布：用 PAT 推送 main、创建 tag 与 Release、上传 jar（Python 标准库，token 不落盘）。<br>One-shot publisher: push main, create tag/Release, upload the jar with a PAT (stdlib only, token never written to disk). |
| `.gitignore` | 排除编译产物与本地日志。<br>Excludes build output and local logs. |
