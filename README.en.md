# wxaudit · Burp Passive Recon Extension v1.1.0

[![CI](https://github.com/devastatingglamour/wxaudit-burp/actions/workflows/ci.yml/badge.svg)](https://github.com/devastatingglamour/wxaudit-burp/actions/workflows/ci.yml) [![Version](https://img.shields.io/github/v/release/devastatingglamour/wxaudit-burp?label=Version)](https://github.com/devastatingglamour/wxaudit-burp/releases/latest)

[中文](README.md) · [File Index](FILES.md)

A passive scanner hooked into Burp Proxy: **only scans the target hosts you configure**, automatically extracts secrets and endpoints from captured responses, unpacks both plaintext and encrypted WeChat mini-program (`wxapkg`) packages, and **optionally uses an LLM to triage false positives and derive full exploit chains for packets you select (off by default)**. Results appear in a custom tab and can be exported to JSON / HTML.

> ⚠️ Exploit chains are for owned or explicitly authorized assets only. AI output is advisory and must be reviewed by a human.

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
5. Deduplicated findings land in the **Findings** tab; each response is also aggregated as a row in the **Packets** tab
6. (Optional) In the **Packets** tab select one or more rows → **AI Analyze Selected** → triage + exploit chain
7. Export JSON / HTML reports (including AI verdicts and suspicious routes)

## Detection (14 rules)

| Group | What it finds |
|---|---|
| secret | Cloud AccessKeys (Alibaba/Tencent/AWS), hardcoded secret/password, JWT, private key headers, session_key |
| pii | ID card numbers, phone numbers, emails, internal IP:port |
| endpoint | Absolute URLs, API base URLs, suspicious API paths, `wx.request/uploadFile` targets, `request/fetch/axios` call paths |

It also extracts hidden routes such as `pages/admin/*` and `pages/test/debug` from `app-config.json` with full context (file/line/snippet/sourceUrl), shown in the detail area and included in reports.

## AI enhancement (optional, off by default)

Network requests are only possible after you check **Enable AI** and fill in the config. With no key or when disabled, **zero requests are sent**; all captured data stays in memory and is never persisted to disk.

| Setting | Description |
|---|---|
| base_url | OpenAI-compatible endpoint, e.g. `https://api.openai.com/v1` or `https://api.deepseek.com/v1` |
| model | e.g. `gpt-4o-mini`, `deepseek-chat` |
| API Key | stored in Burp extension settings, never logged or written to disk |
| timeout / batch / max_tokens | dual timeouts, chunk size, output cap |
| realtime | off by default; when on, each packet is analyzed asynchronously (adds cost) |
| exploit chain | on by default; asks the AI for a full exploit chain |

Usage: switch to the **Packets (select for AI)** tab, select one or more rows, click **AI Analyze Selected**. Results appear in the detail pane — false-positive triage (verdict/confidence/reason) and exploit chain (vuln type/preconditions/steps/expected result/risk level) — and are included in exports. Model output is strict JSON with one automatic retry on parse failure. Bearer tokens, password/secret values and JWTs are redacted before sending. Data is wrapped in untrusted-data markers with instruction-ignoring rules to mitigate prompt injection.

## Panel guide

- **Target URLs / AppID** — scope and decryption credentials
- **AI enhancement** — endpoint, model, key, and toggles
- **Findings / Packets** — two tabs: per-finding and per-response
- **Apply Target** — save and activate immediately
- **Filter** — by severity (high/medium/low/info) or group (secret / endpoint / pii)
- **AI Analyze Selected** — triage + exploit chain for selected packets
- **Export JSON / HTML** — report of all findings, AI verdicts, and suspicious routes
- **Clear Results** — clears findings, packets and counters, keeps target config
- **Detail** — rule name, matched value, source location, context, AI analysis, hidden routes
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
- AI triage and exploit chains can produce false positives/negatives; human review is required
- With AI enabled, selected data is sent to the third-party endpoint you configured
- Burp's Extender API exposes no history timestamp; the extension analyzes in-memory packets only and does not read Burp history
- Responses over 8 MB are skipped; binary bodies are not scanned

## Legal

Use only on systems you own or are explicitly authorized to test. The exploit-chain feature is for authorized security assessments only; users must obtain written authorization and comply with applicable law. Report discovered keys/tokens through proper channels; do not reuse them for unauthorized access.
