# v1.0.0 发布说明 / Release Notes

> 在 GitHub Release 页面新建 Release 时，直接复制下面中英文内容即可。
> Copy the Chinese and English sections below when creating the Release on GitHub.

## Release 标题 / Title

```
v1.0.0 - 首个稳定版 / First Stable Release
```

## 说明正文 / Body

```markdown
## 中文

wxaudit 是挂在 Burp Proxy 上的被动侦察扩展：**只扫你指定的目标网址**，自动提取 JS / 小程序包里的敏感信息与接口，明文与加密 wxapkg 自动解包脱壳。

- 目标作用域：精确 host、子域通配、路径前缀；未配置目标时不扫描任何包
- 解密：PBKDF2-HMAC-SHA1 + AES-256-CBC + XOR，AppID 自动从流量提取并缓存，支持手填
- 检测：14 条规则（云密钥 / 硬编码 secret / JWT / PII / 接口路径）+ 隐藏路由发现
- 结果：自定义 Tab、分类筛选、详情、日志、JSON / HTML 导出

安装：下载下方 jar，在 Burp 中 Extender → Extensions → Add → Java 加载。

验收：三轮沙盒测试全部通过（编译、105 项断言、真实 Burp API 兼容、可复现构建、从交付 jar 直接加载）。
SHA256: 06477ddb0bc2448eb33629c59b7e2c3566889d2e17ad9b9124cd0c4b2a0df0d5

仅用于自有或已授权目标。详见 README.md。

## English

wxaudit is a passive recon extension for Burp Proxy. It **only scans the target URLs you configure**, automatically extracts secrets and endpoints from JS / mini-program packages, and unpacks both plaintext and encrypted wxapkg files.

- Target scope: exact host, subdomain wildcard, path prefix; scans nothing when no target is configured
- Decryption: PBKDF2-HMAC-SHA1 + AES-256-CBC + XOR, AppID auto-extracted from traffic with per-host cache and manual override
- Detection: 14 rules (cloud keys / hardcoded secrets / JWT / PII / endpoint paths) plus hidden-route discovery
- Results: custom tab, category filters, detail view, log, JSON / HTML export

Install: download the jar below, then in Burp go to Extender → Extensions → Add → Java.

Verification: three sandbox acceptance rounds all passed (compile, 105 assertions, real Burp API compatibility, reproducible build, direct load from delivered jar).
SHA256: 06477ddb0bc2448eb33629c59b7e2c3566889d2e17ad9b9124cd0c4b2a0df0d5

Use only on systems you own or are authorized to test. See README.en.md.
```

## Release 需上传的附件 / Asset to attach

- `wxaudit-burp.jar`（本地路径：`D:\ai\workbuddy\2026-11-20-11-54-18\wxaudit-burp\wxaudit-burp.jar`）
- SHA256：`06477ddb0bc2448eb33629c59b7e2c3566889d2e17ad9b9124cd0c4b2a0df0d5`

## 网页操作步骤 / Web steps

1. 打开 `https://github.com/devastatingglamour/wxaudit-burp/releases`
2. 点 **Draft a new release**
3. Tag 填 `v1.0.0`，标题和说明复制上面内容
4. 拖入 `wxaudit-burp.jar` 作为附件
5. 点 **Publish release**
