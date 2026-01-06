## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2025-01-06 - [SSRF via Redirects and Feedparser]
**Vulnerability:** The application used `is_safe_url` to check URLs before fetching, but `requests.get(allow_redirects=True)` does not re-validate the URL after a redirect. This allows an attacker to bypass SSRF protection by providing a safe URL that redirects to an internal IP (e.g., 127.0.0.1). Additionally, passing a URL directly to `feedparser` could bypass controls if `feedparser` handles fetches internally.
**Learning:** Checking a URL once is insufficient if the HTTP client follows redirects automatically. DNS rebinding and redirects can switch the target from a public IP to a private one after the initial check.
**Prevention:**
1. Use a custom `safe_requests_get` function that disables automatic redirects.
2. Manually handle redirects in a loop, validating `is_safe_url` for every new location header.
3. Fetch content using this safe function first, then pass the bytes to libraries like `feedparser`, rather than letting them handle the network transport.
