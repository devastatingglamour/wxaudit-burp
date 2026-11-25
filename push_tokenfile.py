#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从本地文件读取 GitHub PAT 并推送 main（token 不进对话/命令行）。
用法: python push_tokenfile.py <token文件路径>
token 文件内容只需一行 ghp_xxx / github_pat_xxx，前后空白会自动去除。
"""
import sys, subprocess, pathlib

def main():
    if len(sys.argv) < 2:
        print("用法: python push_tokenfile.py <token文件路径>")
        sys.exit(1)
    p = pathlib.Path(sys.argv[1]).expanduser()
    if not p.exists():
        print("token 文件不存在:", p)
        sys.exit(1)
    token = p.read_text(encoding="utf-8").strip().splitlines()[0].strip()
    if not token:
        print("token 文件为空")
        sys.exit(1)
    masked = token[:4] + "…" + token[-4:]
    print("使用 token:", masked)

    # 1) 先验证 token
    import json, urllib.request, urllib.error
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={"User-Agent": "push", "Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json"})
    try:
        login = json.loads(urllib.request.urlopen(req, timeout=30).read())["login"]
        print("认证成功:", login)
    except Exception as e:
        print("认证失败:", str(e)[:120])
        sys.exit(2)

    # 2) git push（token 只在进程内存里，URL 不打印）
    remote = "https://x-access-token:%s@github.com/devastatingglamour/wxaudit-burp.git" % token
    proc = subprocess.run(
        ["git", "push", remote, "main"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (proc.stdout + proc.stderr)
    for line in out.splitlines():
        print("  " + line.replace(token, "<redacted>"))
    if proc.returncode != 0:
        print("推送失败")
        sys.exit(3)
    print("推送成功")

if __name__ == "__main__":
    main()
