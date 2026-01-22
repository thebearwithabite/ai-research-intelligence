## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-22 - [SSRF via HTTP Redirects]
**Vulnerability:** The application validated URLs against private IPs before requesting, but used standard `requests.get` which follows redirects by default. An attacker could provide a safe URL (e.g., `http://attacker.com`) that redirects to a private IP (e.g., `http://169.254.169.254`), bypassing the initial check (Time-of-Check Time-of-Use).
**Learning:** Validating only the initial URL is insufficient for SSRF protection when using libraries that automatically follow redirects.
**Prevention:**
1. Disable automatic redirects (`allow_redirects=False`).
2. Manually handle redirects in a loop.
3. Validate the `Location` header of every redirect hop against the allowlist/blocklist before following it.
