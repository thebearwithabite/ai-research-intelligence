## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2024-05-24 - [SSRF Bypass via Redirects]
**Vulnerability:** The `is_safe_url` check was susceptible to Time-of-Check Time-of-Use (TOCTOU) and bypass via HTTP redirects. `requests.get` follows redirects by default, allowing an attacker to provide a safe URL (e.g., their own server) that redirects to an unsafe internal IP (e.g., `169.254.169.254` or `localhost`).
**Learning:** Checking a URL before fetching it is insufficient if the fetching library follows redirects automatically. Validation must occur at *every* hop of the redirect chain.
**Prevention:**
1. Disable automatic redirects in the HTTP client (`allow_redirects=False`).
2. Implement a wrapper (like `safe_requests_get`) that manually handles redirects.
3. Validate the `Location` header of every redirect against the security policy before following it.
