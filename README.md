# wxaudit Burp Extension v1.1.0

[![CI](https://github.com/devastatingglamour/wxaudit-burp/actions/workflows/ci.yml/badge.svg)](https://github.com/devastatingglamour/wxaudit-burp/actions/workflows/ci.yml)

挂在 Burp Proxy 上的被动侦察扩展：**只扫你指定的目标网址**，自动提取 JS 与小程序包里的敏感信息和接口，明文与加密 wxapkg 自动解包脱壳；**可选接入大模型对所选数据包做误报研判与完整利用链分析（默认关闭）**。 / A passive recon extension for Burp Proxy that **only scans the target URLs you configure**, extracts secrets and endpoints from JS and mini-program packages, auto-unpacks plaintext and encrypted wxapkg files, and **optionally uses an LLM to triage false positives and derive full exploit chains for selected packets (off by default)**.

> ⚠️ 完整利用链仅用于自有或已明确授权的资产；AI 输出仅供参考，必须人工复核。 / Exploit chains are for owned or explicitly authorized assets only; AI output is advisory and must be reviewed by a human.

从 [Releases](../../releases) 下载 `wxaudit-burp.jar`，在 Burp 中 **Extender → Extensions → Add → Java** 加载；加载后出现 **wxaudit** 标签页。 / Download the jar from Releases and load it via **Extender → Extensions → Add → Java**; a **wxaudit** tab then appears.

完整中英双语文件索引见 [FILES.md](FILES.md)。 / See [FILES.md](FILES.md) for the complete bilingual file index.

## 仓库结构与文件简介 / Repository layout

| 文件 / 文件夹 | 中文简介 / English |
|---|---|
| `src/wxaudit/` | Burp 扩展源码（含 AI 增强）/ Burp extension source (incl. AI enhancement) |
| `stub/burp/` | Burp 接口编译桩（不进 jar）/ Burp API compile-time stubs (not shipped) |
| `test/wxaudit/` | 自动化测试（含 AI mock 测试）/ Automated tests (incl. AI mock tests) |
| `.github/workflows/ci.yml` | GitHub Actions 持续集成 / GitHub Actions continuous integration |
| `.gitignore` | Git 忽略规则 / Git ignore rules |
| `CONTRIBUTING.md` | 贡献与发布流程 / Contribution and release process |
| `FILES.md` | 全部文件的中英双语简介 / Bilingual descriptions for all files |
| `LICENSE` | MIT 许可证 / MIT License |
| `SECURITY.md` | 安全策略 / Security policy |
| `README.en.md` | 英文使用说明 / English usage guide |
| `README.md` | 本文件 / This file |
| `build.sh` | 编译、测试与打包脚本 / Build, test, and packaging script |
| `pack.py` | 可复现打包脚本 / Reproducible packaging script |
| `release.py` | 一键发布脚本 / One-shot release script |
| `verify.sh` | 三轮验收脚本 / Three-round verification script |

## 第一步：配置目标 / Step 1: Configure the target

打开 **wxaudit** 标签，在「目标网址」框填要测的域名，点 **应用目标**。 / Open the **wxaudit** tab, enter the domains under test in the target box, and click **Apply Target**.

**未配置目标时不扫描任何包**，避免无关流量混入结果。 / **With no target configured, nothing is scanned** — unrelated traffic never enters the results.

```text
api.example.com              # 该域名及所有子域 / host and all subdomains
*.other.com                  # 仅子域，不含主域 / subdomains only
https://m.other.com/app/v1   # 指定 host + 路径前缀 / exact host + path prefix
```

目标配置持久化，重启自动恢复。 / Targets persist across restarts.

加密 wxapkg 需要小程序 AppID：扩展自动从请求 URL / body 抓取并按 host 缓存，抓不到可在面板手填。 / Encrypted wxapkg needs the mini-program AppID: it is auto-extracted from request URLs/bodies and cached per host, or entered manually in the panel.

## 工作流 / Workflow

1. 浏览器 / 小程序代理走 Burp，正常抓包 / Route browser or mini-program traffic through Burp
2. 只处理命中目标 URL 的响应，其他计为跳过 / Process only in-scope responses; count the rest as skipped
3. JS / JSON / HTML 直接正则扫描 / Regex-scan JS, JSON, and HTML bodies
4. wxapkg 按魔数识别解包；加密包用 AppID 解密 / Unpack wxapkg by magic bytes; decrypt with AppID when needed
5. 结果去重进「扫描结果」表，每个响应同时聚合为「数据包」/ Deduplicate into the Findings table; each response is also aggregated as a Packet
6. （可选）在「数据包」视图选包 → 点「AI 分析选中包」→ 误报研判 + 利用链 / (Optional) select packets → "AI Analyze Selected" → triage + exploit chain
7. 导出 JSON / HTML 报告（含 AI 结论与可疑路由）/ Export JSON or HTML reports (incl. AI verdicts and routes)

## 检测内容 / Detection

| 分类 / Group | 内容 / What it finds |
|---|---|
| secret | 云 AccessKey、硬编码 secret/password、JWT、私钥、session_key / Cloud keys, hardcoded secrets, JWT, private keys, session_key |
| pii | 身份证、手机号、邮箱、内网 IP:端口 / ID cards, phones, emails, internal IPs |
| endpoint | 绝对 URL、API BaseURL、可疑路径、`wx.request` / `fetch` / `axios` 目标 / Absolute URLs, base URLs, suspicious paths, request targets |

另从 `app-config.json` 提取 `pages/admin/*` 等隐藏路由（带 file/line/snippet/sourceUrl 上下文）。 / Hidden routes such as `pages/admin/*` are also extracted from `app-config.json` (with file/line/snippet/sourceUrl context).

## AI 智能增强（可选，默认关闭）/ AI enhancement (optional, off by default)

在面板的「AI 增强」区配置并勾选「启用 AI 分析」后，才可能发出网络请求；未启用或未填 Key 时**零外发**。 / Network requests are only possible after you check "Enable AI" and fill the config; with no key or disabled, **zero requests are sent**.

| 配置项 / Setting | 说明 / Description |
|---|---|
| base_url | OpenAI 兼容端点，如 `https://api.openai.com/v1` / `https://api.deepseek.com/v1` / OpenAI-compatible base URL |
| 模型 / model | 如 `gpt-4o-mini`、`deepseek-chat` / model name |
| API Key | 存于 Burp 扩展设置，不写日志、不落盘 / stored in Burp settings, never logged or persisted to disk |
| 超时 / 每批 / max_tokens | 双超时、分块大小、输出上限 / dual timeout, chunk size, output cap |
| 实时逐条 / realtime | 默认关；开启后每包异步分析（增加费用）/ off by default; async per-packet analysis |
| 生成利用链 / exploitChain | 默认开；要求 AI 输出完整利用链 / on by default; requests a full exploit chain |

用法：切到「**数据包（选包做 AI 分析）**」标签，多选一行或多行，点「**AI 分析选中包**」。结果在详情区展示误报研判（结论/置信度/理由）与利用链（漏洞类型/前置条件/测试步骤/预期结果/风险等级），并计入报告。 / Switch to the **Packets** tab, select one or more rows, click **AI Analyze Selected**. Results appear in the detail pane (verdict/confidence/reason and exploit chain: vuln type/preconditions/steps/expected result/risk) and are included in exports.

模型输出为严格 JSON，解析失败自动重试一次；发送前对 Bearer Token、password/secret、JWT 等做掩码。数据用不可信标记包裹并声明忽略其中指令以防 prompt 注入。 / Model output is strict JSON with one retry on parse failure; bearer tokens, password/secret values and JWTs are redacted before sending. Data is wrapped in untrusted-data markers with instruction-ignoring rules to mitigate prompt injection.

## 面板 / Panel

- **目标网址 / AppID** — 配置作用域与解密凭据 / scope and decryption credentials
- **AI 增强** — 端点、模型、Key、开关 / endpoint, model, key, toggles
- **扫描结果 / 数据包** — 两个标签页：结果按条、数据包按响应 / two tabs: per-finding and per-response
- **筛选** — 按等级或分类 / filter by severity or group
- **AI 分析选中包** — 对所选数据包做研判与利用链 / triage + exploit chain for selected packets
- **导出 JSON / HTML** — 全部结果、AI 结论与可疑路由 / all findings, AI verdicts and routes
- **详情 / 日志** — 上下文、AI 分析、跳过与解密失败原因 / context, AI analysis, and failure reasons

## 构建与验收 / Build and verification

需要 JDK8、Python 3 与 Burp 自带 JRE21。 / Requires JDK8, Python 3, and Burp's bundled JRE21.

```bash
bash build.sh    # 编译 + 全部测试 + 打包 / compile, test, package
bash verify.sh   # 三轮独立验收 / three acceptance rounds
```

## 局限 / Limitations

- 纯静态正则，不做 JS 反混淆 / Static regex only; no JS deobfuscation
- AI 研判与利用链存在误报/漏报，需人工复核 / AI triage and chains can be wrong; human review required
- 启用 AI 后所选数据会发往你配置的第三方端点 / with AI enabled, selected data is sent to your configured third-party endpoint
- PC 微信本地缓存加密包不经过 Burp，无法扫描 / PC WeChat local-cache packages never reach Burp
- Burp API 不暴露历史时间戳，扩展只分析内存中的数据包，不读 Burp history / Burp API exposes no history timestamp; extension analyzes in-memory packets only
- 超过 8 MB 的响应跳过，二进制不扫描 / Responses over 8 MB skipped; binary bodies ignored

## 合规 / Legal

仅用于自有或已明确授权的目标。完整利用链功能仅供授权安全评估，用户须自行取得书面授权并遵守适用法律。 / Use only on systems you own or are explicitly authorized to test. The exploit-chain feature is for authorized security assessments only; users must obtain written authorization and comply with applicable law.

<!-- 用途：项目介绍、安装方法与文件索引 / Project overview, installation, and file index | -->
