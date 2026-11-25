# 文件索引 / File Index

> 每个条目先中文说明，再英文说明。/ Each entry gives Chinese first, then English.

## 源码 / Source (`src/wxaudit/`)

| 文件 / File | 说明 / Description |
|---|---|
| `BurpExtender.java` | **扩展入口**：注册代理监听器与自定义 Tab，按目标过滤响应，调度解密解包与扫描，维护去重结果、数据包缓存和统计；用户选包后经 SwingWorker 触发 AI 分析（可选实时）。<br>**Entry point**: registers the proxy listener and custom tab, filters responses by target scope, orchestrates decryption/unpacking/scanning, keeps deduplicated results, packet cache and counters; triggers AI analysis on user-selected packets via SwingWorker (optional realtime). |
| `ScopeFilter.java` | **作用域过滤**：解析目标网址（精确 host、子域通配、路径前缀），判断请求 URL 是否命中。<br>**Scope filter**: parses target URLs (exact host, subdomain wildcard, path prefix) and decides whether a request URL is in scope. |
| `Crypto.java` | **解密层**：PBKDF2-HMAC-SHA1 派生密钥、AES-256-CBC/NoPadding 解密、尾部 XOR；含魔数与 gzip 识别。全部用 JDK 标准库。<br>**Crypto layer**: PBKDF2-HMAC-SHA1 key derivation, AES-256-CBC/NoPadding decryption, tail XOR; magic-byte and gzip detection. JDK standard library only. |
| `Wxapkg.java` | **解包器**：内存中解析 wxapkg 索引表，还原文件路径与内容，提取其中 appid；含测试用明文包构造器。<br>**Unpacker**: parses the wxapkg index table in memory, restores file paths and contents, extracts embedded appid; includes a plaintext package builder for tests. |
| `Rules.java` | **检测规则**：14 条正则（secret / pii / endpoint 三类）及降噪白名单，从 Python 版移植并用标准向量验证。<br>**Detection rules**: 14 regex rules in three groups (secret / pii / endpoint) plus noise filters, ported from the Python version and verified with standard vectors. |
| `Scanner.java` | **扫描引擎**：文本扫描、行号与上下文提取、结果去重排序、从 `app-config.json` 提取可疑路由。<br>**Scan engine**: text scanning, line numbers and snippets, result deduplication/sorting, and hidden-route extraction from `app-config.json`. |
| `UiPanel.java` | **Swing 面板**：目标配置、AppID 输入、结果表格、筛选、详情、日志、导出按钮；所有更新在 EDT 线程。<br>**Swing panel**: target config, AppID input, result table, filters, detail view, log, export buttons; all mutations run on the EDT. |
| `Exporter.java` | **报告导出**：手写 JSON 转义与自包含浅色主题 HTML 报告，含 AI 研判/利用链与可疑路由两表，保留旧签名兼容测试，零第三方依赖。<br>**Report export**: hand-written JSON escaping and self-contained light-theme HTML reports with AI verdict/chain and suspicious-route tables; legacy signatures kept for tests, no third-party deps. |
| `Json.java` | **极简 JSON**：零依赖解析/序列化，支持转义、`\uXXXX`、剥代码围栏；解析模型输出与配置。<br>**Minimal JSON**: dependency-free parse/serialize with escapes, `\uXXXX`, fence stripping; parses model output and config. |
| `AiConfig.java` | **AI 配置**：端点/模型/Key/开关/超时/分块/利用链开关，默认禁用，JSON 往返，存 Burp 扩展设置。<br>**AI config**: endpoint/model/key/toggles/timeouts/chunk/chain flag, disabled by default, JSON round-trip, stored in Burp settings. |
| `CapturedPacket.java` | **数据包旁路结构**：内存保存方法、脱敏请求头/响应摘要、关联 Finding 键与路由，有界截断，不落盘。<br>**Packet side-car**: in-memory method, redacted request/response excerpts, linked finding keys and routes, bounded truncation, never persisted. |
| `RouteFinding.java` | **可疑路由上下文**：route/file/line/snippet/sourceUrl，替代旧裸字符串。<br>**Route context**: route/file/line/snippet/sourceUrl, replacing the old bare string. |
| `AiTriage.java` | **误报研判结论**：总体结论、置信度、理由、逐条 Finding 判定。<br>**Triage verdict**: overall verdict, confidence, reason, per-finding decisions. |
| `AiChain.java` | **利用链结论**：漏洞类型、前置条件、有序步骤、预期结果、风险等级、摘要（仅授权目标）。<br>**Exploit chain**: vuln type, preconditions, ordered steps, expected result, risk level, summary (authorized targets only). |
| `AiResult.java` | **结果信封**：单包研判+利用链、原始输出与错误，失败可降级。<br>**Result envelope**: per-packet triage + chain, raw output and error for graceful degradation. |
| `AiResultStore.java` | **内存结果仓**：以 packetId 为键的并发 Map，统计误报数，不落盘。<br>**In-memory result store**: concurrent map keyed by packetId, false-positive count, never persisted. |
| `LlmClient.java` | **HTTP 客户端**：仅用 `HttpURLConnection` POST `/chat/completions`，Bearer 鉴权、双超时、错误码分类、响应上限；构造不联网。<br>**HTTP client**: `HttpURLConnection` POST to `/chat/completions` only, bearer auth, dual timeouts, error classification, response cap; constructor never connects. |
| `AiPrompts.java` | **提示词与脱敏**：授权 framing、不可信数据隔离标记、严格 JSON schema、Bearer/secret/JWT 掩码。<br>**Prompts and redaction**: authorization framing, untrusted-data markers, strict JSON schema, bearer/secret/JWT redaction. |
| `AiAnalyzer.java` | **分析编排**：分块批量、prompt 构建、响应解析、失败重试一次、按 packetId 归位。<br>**Analysis orchestrator**: chunked batching, prompt building, response parsing, one retry, results keyed by packetId. |

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
| `JarLoadTest.java` | 第三轮：从交付 jar 直接加载扩展与 AI 类、校验默认禁用、驱动模拟响应。<br>Round 3: load the extension and AI classes from the delivered jar, verify default-disabled, drive a mocked response. |
| `AiTest.java` | AI 增强 68 项：本地 mock OpenAI 端点、正常/错误码/超时/畸形重试/关闭零请求/去重/分块/利用链解析/路由上下文/导出。<br>68 AI assertions: local mock OpenAI endpoint, success/errors/timeout/malformed-retry/zero-requests-when-disabled/dedupe/chaining/chain parsing/route context/export. |

## 脚本与文档 / Scripts & docs

| 文件 / File | 说明 / Description |
|---|---|
| `build.sh` | 编译、五类测试（含 AI mock）、API 兼容校验、打包。<br>Compile, run five test groups (incl. AI mock), check API compatibility, package the jar. |
| `verify.sh` | 三轮验收：全量构建（含 AI mock 标记）、可复现性与产物完整性、真实 JRE 从 jar 加载。<br>Three acceptance rounds: full build (with AI mock marker), reproducibility/integrity, real-JRE load from jar. |
| `pack.py` | 以固定时间戳写 JAR(ZIP)，保证构建字节级可复现。<br>Writes the JAR (ZIP) with fixed timestamps for byte-for-byte reproducible builds. |
| `.github/workflows/ci.yml` | GitHub Actions 持续集成：编译、四组 mock 测试（含 AI）、可复现打包校验。<br>GitHub Actions CI: compile, four mocked test groups (incl. AI), reproducible packaging check. |
| `README.md` / `README.en.md` | 中文 / 英文使用说明。<br>Chinese / English usage guide. |
| `CONTRIBUTING.md` | 贡献与发布流程、版本规则、安全注意。<br>Contribution and release process, versioning, safety notes. |
| `SECURITY.md` | 安全策略：授权使用、数据处理、漏洞报告方式。<br>Security policy: authorized use, data handling, vulnerability reporting. |
| `LICENSE` | MIT 许可证（标准英文法律文本）。<br>MIT license (standard English legal text). |
| `release.py` | 一键发布：用 PAT 推送 main、创建 tag 与 Release、上传 jar（Python 标准库，token 不落盘）。<br>One-shot publisher: push main, create tag/Release, upload the jar with a PAT (stdlib only, token never written to disk). |
| `push_tokenfile.py` | 本地发布凭据辅助脚本，不将凭据提交到仓库。<br>Local release credential helper; credentials stay out of the repository. |
| `.gitignore` | 排除编译产物与本地日志。<br>Excludes build output and local logs. |
