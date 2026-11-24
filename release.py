#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One-shot publisher for wxaudit-burp (stdlib only, no third-party deps).

What it does, in order:
  1. Push local `main` (already committed) to GitHub using the supplied PAT
  2. Create the v1.0.0 Release (auto-creates the tag on default branch HEAD)
  3. Upload wxaudit-burp.jar as a release asset

Usage:
  GITHUB_TOKEN=<pat> python release.py
or:
  python release.py <pat>

The token is never written to disk or printed. Requires: `git`, Python 3,
and a PAT with the `repo` scope (fine-grained PAT: Contents=read/write).
"""
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

OWNER = "devastatingglamour"
REPO = "wxaudit-burp"
BRANCH = "main"
TAG = "v1.0.0"
TITLE = "v1.0.0 - 首个稳定版 / First Stable Release"
JAR = "wxaudit-burp.jar"
SHA256 = "06477ddb0bc2448eb33629c59b7e2c3566889d2e17ad9b9124cd0c4b2a0df0d5"

BODY = """## 中文

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
"""


def api(url, token, method="GET", payload=None, headers=None, raw=None, ctype=None):
    data = raw if raw is not None else (json.dumps(payload).encode("utf-8") if payload is not None else None)
    h = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "wxaudit-publisher",
    }
    if ctype:
        h["Content-Type"] = ctype
    elif payload is not None:
        h["Content-Type"] = "application/json"
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        print("  HTTP %s %s -> %s %s" % (method, url, e.code, detail[:400]))
        raise


def main():
    token = os.environ.get("GITHUB_TOKEN") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not token:
        print("ERROR: provide PAT via GITHUB_TOKEN env or first argument")
        sys.exit(2)
    redacted = token[:4] + "***" + token[-4:]

    print("[1/3] push main -> https://github.com/%s/%s" % (OWNER, REPO))
    push_url = "https://x-access-token:%s@github.com/%s/%s.git" % (token, OWNER, REPO)
    p = subprocess.run(
        ["git", "push", push_url, "main:" + BRANCH],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    # scrub token from any git output before printing
    out = p.stdout.replace(token, redacted)
    print(out.strip())
    if p.returncode != 0:
        print("ERROR: git push failed")
        sys.exit(1)

    print("[2/3] create release " + TAG)
    rel_url = "https://api.github.com/repos/%s/%s/releases" % (OWNER, REPO)
    status, rel = api(rel_url, token, method="POST", payload={
        "tag_name": TAG,
        "name": TITLE,
        "body": BODY,
        "draft": False,
        "prerelease": False,
    })
    print("  release created: %s (id=%s)" % (rel.get("html_url"), rel.get("id")))

    print("[3/3] upload asset " + JAR)
    with open(JAR, "rb") as f:
        jar_bytes = f.read()
    up_url = "https://uploads.github.com/repos/%s/%s/releases/%s/assets?name=%s" % (
        OWNER, REPO, rel["id"], JAR)
    status, asset = api(up_url, token, method="POST", raw=jar_bytes,
                        ctype="application/java-archive")
    print("  asset uploaded: %s (%d bytes)" % (asset.get("browser_download_url"), len(jar_bytes)))

    print("")
    print("DONE")
    print("  repo:    https://github.com/%s/%s" % (OWNER, REPO))
    print("  release: %s" % rel.get("html_url"))
    print("  jar:     %s" % asset.get("browser_download_url"))
    print("  sha256:  %s" % SHA256)


if __name__ == "__main__":
    main()
