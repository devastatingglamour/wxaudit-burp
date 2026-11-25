# 安全策略 / Security Policy

## 授权使用 / Authorized Use

本项目仅用于自有或已授权目标的安全测试。用户有责任取得明确授权并遵守批准的范围。
This project is for security testing of systems you own or are authorized to test. Users are responsible for obtaining explicit authorization and staying within the approved scope.

## 数据处理 / Data Handling

- 不要提交真实 AppID、令牌、Cookie、抓包数据或真实用户数据。 / Never commit real AppIDs, tokens, cookies, captured traffic or real user data.
- 自动化测试使用合成的 wxapkg 与虚构数据。 / Automated tests use synthetic wxapkg files and fictitious data.
- 扫描结果可能包含敏感信息，分享前需人工审查和脱敏。 / Scan results may contain secrets; review and redact before sharing.
- 扩展仅做静态分析，不主动发送任何请求。 / The extension performs static analysis only and sends no requests on its own.

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
