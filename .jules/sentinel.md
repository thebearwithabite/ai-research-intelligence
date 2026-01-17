## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-17 - [SSRF Bypass via Redirects]
**Vulnerability:** The `is_safe_url` check was only performed on the initial URL. `requests` and `feedparser` automatically follow redirects by default. An attacker could provide a safe URL (e.g., `http://attacker.com`) that redirects to a sensitive internal IP (e.g., `http://169.254.169.254`), bypassing the initial security check.
**Learning:** Checking the URL once is insufficient because the HTTP client's redirect behavior can be exploited. `feedparser` also handles network requests internally, obscuring this behavior.
**Prevention:**
1. Do not rely on default redirect handling for user-provided URLs.
2. Implement a safe wrapper (e.g., `safe_requests_get`) that manually processes redirects and re-validates the URL at every hop.
3. For libraries like `feedparser`, fetch the content safely first using the wrapper, then pass the raw data to the library to parse.
