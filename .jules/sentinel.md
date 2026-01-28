## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-28 - [SSRF Protection in Redirects]
**Vulnerability:** The application used `requests.get()` and `feedparser.parse()` directly on user-provided URLs. `requests` follows redirects by default, and `feedparser` fetches internally, both bypassing the initial `is_safe_url` check if a redirect occurs to an internal IP (SSRF).
**Learning:** Checking a URL against an allowlist/denylist once is insufficient if the client follows redirects automatically. An attacker can provide a safe URL that redirects to an unsafe internal IP (e.g., `169.254.169.254`).
**Prevention:**
1. Use `allow_redirects=False` in `requests`.
2. Implement a loop to manually follow redirects.
3. Validate the `Location` header against the safety check (`is_safe_url`) at *every* hop.
4. Strip sensitive headers (like `Authorization`) when redirecting across domains to prevent credential leakage.
