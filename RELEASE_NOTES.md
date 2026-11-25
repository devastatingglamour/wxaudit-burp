# v1.1.0 发布说明 / Release Notes

> 在 GitHub Release 页面新建 Release 时，直接复制下面中英文内容即可。
> Copy the Chinese and English sections below when creating the Release on GitHub.

## Release 标题 / Title

```
v1.1.0 - AI 研判与接口利用链 / AI Triage and Exploit Chains
```

## 说明正文 / Body

```markdown
## 中文

wxaudit v1.1.0 在原有被动侦察能力上新增**可选的大模型智能分析（默认关闭）**：

- **AI 二次研判**：对静态命中判误报、给理由；「数据包」视图多选后点「AI 分析选中包」批量送 AI
- **完整利用链**：授权白帽视角输出漏洞类型、前置条件、有序测试步骤、预期结果与风险等级
- **可疑路由升级**：从 app-config.json 提取的路由带 file/line/snippet/来源 URL 上下文，并入导出与 AI 分析
- **OpenAI 兼容端点**：base_url / 模型 / Key / 超时 / 分块 / 利用链开关，存 Burp 扩展设置；可选实时逐条（默认关）
- 保留 v1.0.0 全部能力：目标作用域过滤、wxapkg 自动解包脱壳、14 条检测规则、JSON/HTML 导出

**隐私与安全**：默认不发任何请求；仅显式启用并填 Key 后，才向自配端点发送脱敏的最小字段，Bearer/secret/JWT 掩码，抓包数据与 AI 结论仅存内存不落盘。

安装：下载下方 jar，在 Burp 中 Extender → Extensions → Add → Java 加载。
验收：三轮沙盒测试全部通过（编译、182 项断言、真实 Burp API 兼容、字节级可复现、从交付 jar 直接加载）。
SHA256: 71f55a4dcfc3b8d2d893d57eec3684baf3e70fdb7005e1abf61e98642a003822

**仅用于自有或已明确授权的资产；AI 输出仅供参考，须人工复核。** 详见 README.md。

## English

wxaudit v1.1.0 adds **optional LLM-powered analysis (off by default)** on top of the passive recon capabilities:

- **AI triage**: false-positive verdicts with reasoning; multi-select rows in the **Packets** tab and click **AI Analyze Selected**
- **Full exploit chains**: authorized white-hat framing — vuln type, preconditions, ordered test steps, expected result and risk level
- **Route upgrade**: routes extracted from app-config.json now carry file/line/snippet/source URL context, included in exports and AI analysis
- **OpenAI-compatible endpoint**: base_url / model / key / timeout / chunk / chain toggle stored in Burp settings; optional realtime per-packet (off by default)
- All v1.0.0 features retained: target scope filtering, wxapkg unpacking/decryption, 14 detection rules, JSON/HTML export

**Privacy & security**: no requests by default; only after explicit opt-in with a key does it send redacted minimal fields to your endpoint (bearer/secret/JWT masked; data and AI results stay in memory, never on disk).

Install: download the jar below, then in Burp go to Extender → Extensions → Add → Java.
Verification: three sandbox acceptance rounds all passed (compile, 182 assertions, real Burp API compatibility, byte-reproducible, direct load from delivered jar).
SHA256: 71f55a4dcfc3b8d2d893d57eec3684baf3e70fdb7005e1abf61e98642a003822

**For owned or explicitly authorized assets only; AI output is advisory and requires human review.** See README.en.md.
```

## Release 需上传的附件 / Asset to attach

- `wxaudit-burp.jar`（本地路径：`D:\ai\workbuddy\2026-11-20-11-54-18\wxaudit-burp\wxaudit-burp.jar`）
- SHA256：`71f55a4dcfc3b8d2d893d57eec3684baf3e70fdb7005e1abf61e98642a003822`

## 网页操作步骤 / Web steps

1. 打开 `https://github.com/devastatingglamour/wxaudit-burp/releases`
2. 点 **Draft a new release**
3. Tag 填 `v1.1.0`，标题和说明复制上面内容
4. 拖入 `wxaudit-burp.jar` 作为附件
5. 点 **Publish release**
