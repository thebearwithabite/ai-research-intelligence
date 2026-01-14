## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-14 - [SSRF Protection for Redirects]
**Vulnerability:** The application was vulnerable to SSRF via DNS Rebinding and HTTP Redirects. `is_safe_url` checked the initial URL, but `requests.get` and `feedparser.parse` would follow redirects to unsafe targets (e.g. `169.254.169.254` or local network) unchecked.
**Learning:** `requests` follows redirects by default without re-validating the destination IP. Standard "check then use" patterns are vulnerable to TOCTOU attacks where the DNS resolution changes or the server redirects to a private IP.
**Prevention:**
1. Implemented `safe_requests_get` which handles redirects manually (`allow_redirects=False`) and validates `is_safe_url` for every hop.
2. Updated `handler.py` to fetch content using `safe_requests_get` first, then pass the content to `feedparser`.
3. Ensured sensitive request parameters (params/data/json) are stripped when following redirects to prevent data leakage.
