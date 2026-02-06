## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-02-06 - [SSRF via feedparser and Requests Redirects]
**Vulnerability:** `feedparser.parse()` and `requests.get()` were used with user-provided URLs. `feedparser` handles fetches internally without SSRF protection, and standard `requests` follows redirects automatically, bypassing initial `is_safe_url` checks if the target redirects to a private IP (e.g. AWS Metadata).
**Learning:** Initial URL validation is insufficient. Libraries that handle their own fetching (like `feedparser`) often lack SSRF controls. Redirects are a major bypass vector.
**Prevention:**
1. Fetch content explicitly using a secured HTTP client before passing to parsers like `feedparser`.
2. Disable automatic redirects (`allow_redirects=False`) and manually validate the `Location` header against the allowlist/blocklist for every hop.
