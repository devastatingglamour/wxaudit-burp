# 验收报告 / Verification Report

> **中文**：发布前在沙盒环境中完成三轮独立验收，全部通过（v1.1.0）。
> **EN**: Three independent acceptance rounds were completed in the sandbox before the v1.1.0 release. All passed.

---

## 轮次 1 — 全量构建与测试 / Round 1 — Full build and test suite

| 项目 / Item | 结果 / Result |
|---|---|
| 编译（JDK8 + 接口桩） / Compile (JDK8 + API stubs) | ✅ PASS |
| 核心自测 25 项 / Core self-tests (25 assertions) | ✅ PASS |
| 模拟抓包端到端 5 项 / Mocked-proxy E2E (5 assertions) | ✅ PASS |
| 边界与异常 49 项 / Boundary & malformed input (49 assertions) | ✅ PASS |
| AI 增强 68 项（本地 mock 端点）/ AI enhancement (68 assertions, local mock) | ✅ PASS |
| 真实 Burp API 兼容性 22 项 / Real Burp API compatibility (22 assertions) | ✅ PASS |
| 打包 / Package | ✅ PASS |

**覆盖 / Coverage**：作用域匹配（子域/通配/路径前缀/大小写/后缀混淆）、wxapkg 明文与加密往返、14 条规则、隐藏路由、去重、超时/超大响应、gzip、二进制跳过、JSON/HTML 转义、Swing 空参数容错、目标内外流量分离；AI：JSON 解析/配置往返/脱敏/默认零请求/成功解析/错误码/超时/畸形重试/分块/利用链字段/prompt 注入隔离/导出集成。

**Coverage**: scope matching, plaintext/encrypted wxapkg roundtrip, 14 rules, hidden routes, dedup, oversized/gzip/binary, JSON/HTML escaping, Swing null-tolerance, in/out-of-scope separation; AI: JSON/config roundtrip, redaction, zero-requests-when-disabled, success, error codes, timeout, malformed retry, chunking, chain fields, prompt-injection markers, export integration.

## 轮次 2 — 可复现性与产物完整性 / Round 2 — Reproducibility and artifact integrity

| 项目 / Item | 结果 / Result |
|---|---|
| 两次构建 SHA256 一致 / Identical SHA256 across two builds | ✅ `71f55a4dcfc3b8d2d893d57eec3684baf3e70fdb7005e1abf61e98642a003822` |
| 交付 jar 不含编译桩 / No stub classes in delivered jar | ✅ PASS |
| 62 个 class 全部在 `wxaudit/` 包内 / 62 classes, all in `wxaudit/` | ✅ PASS |
| jar 大小 91,888 字节 / Size 91,888 bytes | ✅ PASS |

> 说明：早期使用 `jar cf` 时 META-INF 时间戳导致哈希漂移，现由 `pack.py` 以固定时间戳写 ZIP，构建完全可复现。
> Note: `jar cf` stamped META-INF with wall-clock time; `pack.py` now writes ZIP entries with fixed timestamps for deterministic builds.

## 轮次 3 — 真实运行环境加载 / Round 3 — Real-runtime loading

使用 Burp 自带 JRE21 + 真实 `burpsuite_pro_org.jar`，直接从交付 jar 加载扩展并驱动模拟代理响应。
Loaded the extension directly from the delivered jar on Burp's bundled JRE21 with the real API jar, then drove a mocked proxy response.

| 项目 / Item | 结果 / Result |
|---|---|
| 从 `wxaudit-burp.jar` 加载 / Loaded from delivered jar | ✅ PASS |
| 8 个 AI 类从 jar 加载 / 8 AI classes loaded from jar | ✅ PASS |
| 默认 AiConfig 网络禁用 / Default AiConfig network-disabled | ✅ PASS |
| `ITab` caption / 标签名 | ✅ `wxaudit` |
| 注册后 UI 组件创建 / UI component after registration | ✅ PASS |
| 模拟 JS 响应扫描出 4 条 / Mocked JS response yielded 4 findings | ✅ PASS |

## 验收结论 / Verdict

**三轮全部通过，允许发布 / All three rounds passed — cleared for release.**

复现命令 / Reproduce:

```bash
bash verify.sh
```

完整日志见 `verification-round1.log`、`verification-round2.log`、`verification-round3.log`（不纳入版本库）。
Full logs are in `verification-round*.log` (excluded from version control).
