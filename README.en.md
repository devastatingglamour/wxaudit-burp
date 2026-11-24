# wxaudit · Burp Passive Recon Extension

[中文](README.md) · [File Index](FILES.md) · [Verification](VERIFICATION.md) · [Changelog](CHANGELOG.md)

A passive scanner hooked into Burp Proxy: **only scans the target hosts you configure**, automatically extracts secrets and endpoints from captured responses, and unpacks both plaintext and encrypted WeChat mini-program (`wxapkg`) packages. Results appear in a custom tab and can be exported to JSON / HTML.

## Installation

Download `wxaudit-burp.jar` from [Releases](../../releases), place it in Burp's extensions directory, then:

**Extender → Extensions → Add → Extension type: Java → select the jar → Next**

On success, Extender's Output shows `wxaudit loaded...` and a new **wxaudit** tab appears. Copying the jar into the directory alone does not load it — you still need to Add it once; Burp remembers it afterwards.

## Step 1: Configure the target (important)

Open the **wxaudit** tab, enter the domains you are testing in the target box, and click **Apply Target**. **With no target configured, the extension scans nothing** and logs the reason — this keeps unrelated traffic out of your results.

```
# match example.com and all its subdomains
api.example.com
# subdomains only, not the apex domain
*.other.com
# exact host with path prefix /app/v1
https://m.other.com/app/v1
```

Targets persist in Burp settings and survive restarts. Clicking Apply Target clears cached AppIDs and traffic counters (results are kept).

**AppID / wxid**: encrypted wxapkg files need the mini-program AppID. The extension extracts `wx` + 16 hex characters from request URLs/bodies and caches them per host. If none can be found, enter it manually in the panel and replay the request. Leaving it blank still works for plaintext packages and JS files.

## Workflow

1. Route browser / mini-program traffic through Burp and browse normally
2. The extension processes only **responses** whose URL matches the target scope; everything else is counted as skipped
3. JS / JSON / HTML responses → regex scan
4. wxapkg → unpack on magic bytes; encrypted packages (URL contains `wxapkg`) → decrypt with AppID, with explicit failure reasons
5. Deduplicated findings land in the table; click a row for context and rule notes
6. Export JSON / HTML reports when needed

## Detection (14 rules)

| Group | What it finds |
|---|---|
| secret | Cloud AccessKeys (Alibaba/Tencent/AWS), hardcoded secret/password, JWT, private key headers, session_key |
| pii | ID card numbers, phone numbers, emails, internal IP:port |
| endpoint | Absolute URLs, API base URLs, suspicious API paths, `wx.request/uploadFile` targets, `request/fetch/axios` call paths |

It also extracts hidden routes such as `pages/admin/*` and `pages/test/debug` from `app-config.json`, shown in the detail area and log.

## Panel guide

- **Target URLs / AppID** — scope and decryption credentials
- **Apply Target** — save and activate immediately
- **Filter** — by severity (high/medium/low/info) or group (secret / endpoint / pii)
- **Export JSON / HTML** — report of all current findings
- **Clear Results** — clears findings and counters only, keeps target config
- **Detail** — rule name, matched value, source location, context, remediation note, hidden routes
- **Log** — discoveries, successful unpacks, and specific reasons for skips / decryption failures

## Build & verification

Requires JDK8 on PATH, Python 3, and Burp's bundled JRE21.

```bash
bash build.sh    # compile + full test suite + package
bash verify.sh   # three independent acceptance rounds (must pass before release)
```

Sources are in `src/wxaudit/`, tests in `test/wxaudit/`. `stub/burp/` contains compile-only API stubs (never shipped in the jar; Burp supplies the real interfaces at runtime). See [FILES.md](FILES.md) for a bilingual per-file index.

## Limitations

- Static regex only — no JS deobfuscation or string-concatenation resolution; `BASE + '/path'` yields only the literal part
- Encrypted packages in the PC WeChat local cache never pass through Burp and cannot be seen; network-distributed packages are usually plaintext
- Encrypted packages without a valid AppID are logged, never silently dropped
- Responses over 8 MB are skipped; binary bodies are not scanned

## Legal

Use only on systems you own or are explicitly authorized to test. Report discovered keys/tokens through proper channels; do not reuse them for unauthorized access.
