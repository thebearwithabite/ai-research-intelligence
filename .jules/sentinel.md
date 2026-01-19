## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-19 - [SSRF via HTTP Redirects]
**Vulnerability:** `requests` and `feedparser` follow redirects by default, bypassing initial URL validation.
**Learning:** Validating only the initial URL is insufficient. Attackers can use a safe URL that redirects to a private IP (e.g., cloud metadata services).
**Prevention:** Implement a custom request wrapper that disables automatic redirects (`allow_redirects=False`) and manually validates the `Location` header of every redirect hop against an allowlist/blocklist.
