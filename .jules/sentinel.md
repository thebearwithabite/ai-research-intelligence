## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2025-05-24 - [SSRF Protection via Safe Redirect Handling]
**Vulnerability:** `requests.get()` automatically follows redirects to potentially unsafe destinations (e.g., internal IPs like `169.254.169.254`), bypassing initial URL validation checks (`is_safe_url`). Additionally, passing URLs directly to libraries like `feedparser` can bypass these checks entirely.
**Learning:** Initial URL validation is insufficient because:
1. HTTP libraries often follow redirects blindly to unsafe targets (Open Redirect vulnerability).
2. Libraries might not implement the same strict checks as your application code.
3. DNS Rebinding attacks can swap the IP address between check and use (TOCTOU).
**Prevention:**
1. Use a custom `safe_requests_get` function that disables automatic redirects (`allow_redirects=False`) and manually validates every URL in the redirect chain.
2. Fetch content using this safe getter first, then pass the *content* (bytes/string) to parsers like `feedparser`, rather than the URL.
3. Validate domain resolution for private IPs as defense-in-depth, even though it doesn't fully solve DNS rebinding without lower-level patching.
