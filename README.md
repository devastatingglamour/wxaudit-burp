# wxaudit Burp Extension v1.0.0

[![CI](https://github.com/devastatingglamour/wxaudit-burp/actions/workflows/ci.yml/badge.svg)](https://github.com/devastatingglamour/wxaudit-burp/actions/workflows/ci.yml)

挂在 Burp Proxy 上的被动侦察扩展：**只扫你指定的目标网址**，自动提取 JS 与小程序包里的敏感信息和接口，明文与加密 wxapkg 自动解包脱壳。 / A passive recon extension for Burp Proxy that **only scans the target URLs you configure**, extracts secrets and endpoints from JS and mini-program packages, and unpacks plaintext and encrypted wxapkg files.

从 [Releases](../../releases) 下载 `wxaudit-burp.jar`，在 Burp 中 **Extender → Extensions → Add → Java** 加载；加载后出现 **wxaudit** 标签页。 / Download the jar from Releases and load it via **Extender → Extensions → Add → Java**; a **wxaudit** tab then appears.

完整中英双语文件索引见 [FILES.md](FILES.md)。 / See [FILES.md](FILES.md) for the complete bilingual file index.

## 仓库结构与文件简介 / Repository layout

| 文件 / 文件夹 | 中文简介 / English |
|---|---|
| `src/wxaudit/` | Burp 扩展源码 / Burp extension source code |
| `stub/burp/` | Burp 接口编译桩（不进 jar）/ Burp API compile-time stubs (not shipped) |
| `test/wxaudit/` | 自动化测试 / Automated tests |
| `.github/workflows/ci.yml` | GitHub Actions 持续集成 / GitHub Actions continuous integration |
| `.gitignore` | Git 忽略规则 / Git ignore rules |
| `CHANGELOG.md` | 版本变更记录 / Changelog |
| `CONTRIBUTING.md` | 贡献与发布流程 / Contribution and release process |
| `FILES.md` | 全部文件的中英双语简介 / Bilingual descriptions for all files |
| `LICENSE` | MIT 许可证 / MIT License |
| `SECURITY.md` | 安全策略 / Security policy |
| `README.en.md` | 英文使用说明 / English usage guide |
| `README.md` | 本文件 / This file |
| `RELEASE_NOTES.md` | 发布说明 / Release notes |
| `VERIFICATION.md` | 三轮验收报告 / Three-round verification report |
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
5. 结果去重进表格，点行看上下文 / Deduplicate into the table; click a row for context
6. 导出 JSON / HTML 报告 / Export JSON or HTML reports

## 检测内容 / Detection

| 分类 / Group | 内容 / What it finds |
|---|---|
| secret | 云 AccessKey、硬编码 secret/password、JWT、私钥、session_key / Cloud keys, hardcoded secrets, JWT, private keys, session_key |
| pii | 身份证、手机号、邮箱、内网 IP:端口 / ID cards, phones, emails, internal IPs |
| endpoint | 绝对 URL、API BaseURL、可疑路径、`wx.request` / `fetch` / `axios` 目标 / Absolute URLs, base URLs, suspicious paths, request targets |

另从 `app-config.json` 提取 `pages/admin/*` 等隐藏路由。 / Hidden routes such as `pages/admin/*` are extracted from `app-config.json`.

## 面板 / Panel

- **目标网址 / AppID** — 配置作用域与解密凭据 / scope and decryption credentials
- **应用目标** — 保存并立即生效 / save and apply immediately
- **筛选** — 按等级或分类 / filter by severity or group
- **导出 JSON / HTML** — 当前全部结果 / export all current findings
- **详情 / 日志** — 上下文、处置建议、跳过与解密失败原因 / context, notes, and failure reasons

## 构建与验收 / Build and verification

需要 JDK8、Python 3 与 Burp 自带 JRE21。 / Requires JDK8, Python 3, and Burp's bundled JRE21.

```bash
bash build.sh    # 编译 + 全部测试 + 打包 / compile, test, package
bash verify.sh   # 三轮独立验收 / three acceptance rounds
```

## 局限 / Limitations

- 纯静态正则，不做 JS 反混淆 / Static regex only; no JS deobfuscation
- PC 微信本地缓存加密包不经过 Burp，无法扫描 / PC WeChat local-cache packages never reach Burp
- 取不到 AppID 的加密包只记日志 / Encrypted packages without AppID are logged, not silently dropped
- 超过 8 MB 的响应跳过，二进制不扫描 / Responses over 8 MB skipped; binary bodies ignored

## 合规 / Legal

仅用于自有或已明确授权的目标。 / Use only on systems you own or are explicitly authorized to test.

<!-- 用途：项目介绍、安装方法与文件索引 / Project overview, installation, and file index | -->
