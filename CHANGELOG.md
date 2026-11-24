# 更新日志 / Changelog

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
