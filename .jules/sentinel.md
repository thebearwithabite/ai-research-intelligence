## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-02-04 - [SSRF Mitigation in Redirects]
**Vulnerability:** Standard `requests.get` and `feedparser.parse` follow redirects automatically, allowing a malicious user to bypass initial URL checks (`is_safe_url`) by redirecting to a private IP (SSRF).
**Learning:** Checking a URL once is not enough if the library follows redirects. Every hop must be validated.
**Prevention:** Use a wrapper like `safe_requests_get` that disables auto-redirects (`allow_redirects=False`) and manually validates the `Location` header of each redirect against the security policy.
