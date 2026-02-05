## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-02-05 - [SSRF via Redirects & DoS Policy]
**Vulnerability:** The application was vulnerable to SSRF because `requests.get` follows redirects by default, bypassing the initial `is_safe_url` check. Also, DoS limits were implemented via silent truncation, contradicting the security policy of explicit error returns.
**Learning:** `requests` (and `feedparser`) are dangerous when handling untrusted URLs even with an initial IP check. A custom "safe getter" that handles redirects manually is required. Also, code behavior should align with documented security policies (truncation vs error).
**Prevention:** Use `safe_requests_get` for all external URL fetching. Ensure input limits trigger explicit errors as per policy.
