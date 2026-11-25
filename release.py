#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One-shot publisher for wxaudit-burp (stdlib only, no third-party deps).

What it does, in order:
  1. Push local `main` (already committed) to GitHub using the supplied PAT
  2. Create the v1.1.0 Release (auto-creates the tag on default branch HEAD)
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
TAG = "v1.1.0"
TITLE = "v1.1.0 - AI 研判与接口利用链 / AI Triage and Exploit Chains"
JAR = "wxaudit-burp.jar"
SHA256 = "71f55a4dcfc3b8d2d893d57eec3684baf3e70fdb7005e1abf61e98642a003822"

BODY = """## 中文

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
