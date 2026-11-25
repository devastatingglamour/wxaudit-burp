# 安全策略 / Security Policy

## 授权使用 / Authorized Use

本项目仅用于自有或已授权目标的安全测试。用户有责任取得明确授权并遵守批准的范围。
This project is for security testing of systems you own or are authorized to test. Users are responsible for obtaining explicit authorization and staying within the approved scope.

## 数据处理 / Data Handling

- 不要提交真实 AppID、令牌、Cookie、抓包数据或真实用户数据。 / Never commit real AppIDs, tokens, cookies, captured traffic or real user data.
- 自动化测试使用合成的 wxapkg 与虚构数据（AI mock 端点在本地回环，无真实 Key）。 / Automated tests use synthetic wxapkg files and fictitious data (the AI mock endpoint is local loopback with no real key).
- 扫描结果可能包含敏感信息，分享前需人工审查和脱敏。 / Scan results may contain secrets; review and redact before sharing.
- **默认不发任何请求**：只有用户显式勾选「启用 AI 分析」并填入 base_url / Key / 模型后，扩展才会向用户自配的 OpenAI 兼容端点发送所选数据包的最小字段（请求方法、脱敏请求头、脱敏响应摘要、命中值/上下文、来源 URL）。Bearer Token、password/secret、JWT 在发送前掩码；不发送完整响应、Cookie。抓包数据与 AI 结论仅存内存，不落盘；API Key 仅存 Burp 扩展设置，不写日志、不入库。 / **No requests by default**: only after the user explicitly enables AI and configures a base_url / key / model does the extension send a minimal set of fields (method, redacted request head, redacted response excerpt, matched values/context, source URL) to the user-configured OpenAI-compatible endpoint. Bearer tokens, password/secret values and JWTs are redacted before sending; full responses and cookies are never sent. Captured data and AI results are memory-only, never persisted; the API key lives only in Burp extension settings, never in logs or the repository.
- 完整利用链功能仅用于自有或已授权目标，AI 输出仅供参考，需人工复核并遵守适用法律。 / The exploit-chain feature is for owned or authorized targets only; AI output is advisory, requires human review, and must comply with applicable law.

## 解密与 AppID / Decryption and AppID

- 加密 wxapkg 的解密依赖目标 AppID，仅可用于已授权的小程序。 / Decrypting encrypted wxapkg requires the target AppID and is only for authorized mini-programs.
- 无法解密时扩展只记录日志，不猜测或爆破密钥。 / When decryption fails the extension only logs the reason; it never guesses or brute-forces keys.

## 报告漏洞 / Reporting a Vulnerability

不要在公开议题中发布凭据或目标数据。私下联系仓库所有者，附带：
Do not post credentials or target data in public issues. Contact the repository owner privately with:

- 受影响版本 / Affected version
- 最小复现步骤 / Minimal reproduction
- 影响 / Impact
- 建议修复措施 / Suggested remediation

不要包含真实用户数据、凭据或未授权的目标详情。 / Never include real user data, credentials or unauthorized target details.

<!-- 用途：安全策略与问题报告方式 / Security policy and vulnerability reporting | -->
