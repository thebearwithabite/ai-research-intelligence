## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-31 - [SSRF via Redirects in Feedparser and Requests]
**Vulnerability:** Standard `requests.get()` and `feedparser.parse()` automatically follow redirects to potentially unsafe locations (e.g., localhost), bypassing initial `is_safe_url()` checks. This allows attackers to perform SSRF attacks using an open redirect on a safe domain.
**Learning:** Checking a URL once before fetching is insufficient. Every hop in a redirect chain must be validated. `feedparser` should never be allowed to fetch URLs directly; always fetch content securely first.
**Prevention:**
1. Use a custom `safe_requests_get` wrapper that disables auto-redirects (`allow_redirects=False`) and manually validates the `Location` header of every redirect.
2. For RSS feeds, fetch the content using the secure wrapper first, then pass the bytes to `feedparser.parse()`.
