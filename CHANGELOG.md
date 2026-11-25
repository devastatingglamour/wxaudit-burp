# 更新日志 / Changelog

## v1.1.0 — 2026-11-25

可选大模型增强版本，向后兼容；AI 默认关闭，不配置 Key 时零外发。/ Optional LLM-enhanced release, backward compatible; AI off by default with zero egress without a key.

**新增 / Added**
- AI 二次研判：对静态命中判误报、重估等级、给理由 / AI triage: false-positive verdict, severity re-ranking, reasoning
- **完整利用链分析**：授权白帽视角输出漏洞类型/前置条件/有序测试步骤/预期结果/风险 / **Full exploit chain**: vuln type, preconditions, ordered steps, expected result, risk (authorized white-hat framing)
- 「数据包」聚合视图：一响应一行，多选后点「AI 分析选中包」批量送 AI / Packets tab: one row per response, multi-select then "AI Analyze Selected" for batch analysis
- OpenAI 兼容端点配置（base_url / 模型 / Key / 超时 / 分块 / 利用链开关），存 Burp 扩展设置 / OpenAI-compatible endpoint config, persisted in Burp settings
- 可疑路由升级为带 file/line/snippet/sourceUrl 的结构，纳入导出与 AI 分析 / Suspicious routes upgraded to context-bearing structures, included in exports and AI
- 可选实时逐条分析（有界线程池，默认关）/ Optional realtime per-packet analysis (bounded pool, off by default)
- AI mock 自动测试 68 项（本地 HttpServer，零外网零真实 Key）/ 68 AI mock assertions via local HttpServer, no external network or real key

**修复 / Fixed**
- 「清空结果」未清表格与数据包列表的 bug / "Clear Results" did not clear the table/packet list
- 详情区用命中值反查 Finding 有歧义，改为按可见行定位 / Detail view located findings by value (ambiguous); now by visible row

**安全 / Security**
- 默认关闭、显式启用才发请求；发送前掩码 Bearer/secret/JWT；数据仅内存不落盘 / Off by default, explicit opt-in; bearer/secret/JWT redacted before send; in-memory only
- prompt 注入隔离（不可信数据标记 + 忽略其中指令）；利用链仅限授权目标 / Prompt-injection isolation and authorized-target-only chains

## v1.0.0 — 2026-11-24

首个正式发布版本。/ First stable release.

**新增 / Added**
- Burp 被动扫描扩展，挂 Proxy 响应自动检测 / Passive Burp extension scanning Proxy responses
- 目标网址作用域过滤：精确 host、子域通配、路径前缀；未配置时不扫描 / Target scope filtering: exact host, subdomain wildcard, path prefix; no scan when unconfigured
- 明文 wxapkg 解包与 PC 加密包解密（PBKDF2 + AES-256-CBC + XOR）/ Plaintext wxapkg unpacking and PC encrypted package decryption
- AppID 从流量自动提取并按 host 缓存，支持手填覆盖 / AppID auto-extraction from traffic with per-host cache and manual override
- 14 条检测规则（secret / pii / endpoint）+ 隐藏路由发现 / 14 detection rules plus hidden-route discovery
- 自定义 Tab：结果表格、分类筛选、详情、日志、JSON/HTML 导出 / Custom tab with result table, filters, detail, log, JSON/HTML export
- 三轮沙盒验收与可复现构建 / Three-round sandbox acceptance and reproducible builds

**修复 / Fixed during acceptance**
- 路径前缀误匹配 `/app/v10` 命中 `/app/v1` / Path-prefix overmatch
- JS 响应内联重复命中未去重 / Duplicate findings within one JS response
- 空文件列表与空 UI 参数导致的 NPE / NPEs on null file lists and null UI arguments

**已知限制 / Known limitations**
- 不做 JS 反混淆；PC 本地缓存加密包不经过 Burp 无法扫描 / No JS deobfuscation; PC local-cache encrypted packages never reach Burp
