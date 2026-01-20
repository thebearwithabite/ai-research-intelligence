## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2024-05-24 - [SSRF Bypass via HTTP Redirects]
**Vulnerability:** `requests.get()` and `feedparser.parse()` follow HTTP redirects by default. An attacker can provide a safe initial URL (e.g., `http://example.com`) that redirects to a private IP (e.g., `http://169.254.169.254`), bypassing initial validation checks.
**Learning:** Validating only the initial URL is insufficient for SSRF protection. Network libraries often abstract away redirects, inadvertently exposing the application to internal network scanning or metadata service exploitation.
**Prevention:**
1. Use a custom network wrapper (e.g., `safe_requests_get`) that disables automatic redirects (`allow_redirects=False`).
2. Manually process redirects in a loop, validating every hop against the allowlist/blocklist (`is_safe_url`).
3. Fetch content using this secure wrapper before passing it to parsers like `feedparser`.
