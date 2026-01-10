## 2026-01-10 - SSRF Bypass via Redirects
**Vulnerability:** External libraries like `feedparser` and `requests` follow HTTP redirects by default, potentially bypassing initial `is_safe_url` checks. An attacker could supply a URL that passes validation but redirects to a private IP (e.g., 127.0.0.1).
**Learning:** Checking a URL before requesting it is insufficient if the client library handles redirects autonomously. TOCTOU issues apply to DNS resolution across redirects.
**Prevention:** Use a wrapper like `safe_requests_get` that disables auto-redirects (`allow_redirects=False`) and validates every hop manually. For `feedparser`, fetch content securely first, then pass the bytes to the parser.
