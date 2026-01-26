## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-26 - [SSRF Protection in Redirects & Feedparser]
**Vulnerability:** `requests.get()` follows redirects by default, allowing attackers to bypass initial SSRF checks (`is_safe_url`) by redirecting to an internal IP (e.g., 169.254.169.254) after the first hop. Additionally, `feedparser.parse(url)` performs its own insecure HTTP requests.
**Learning:** Checking a URL once before fetching is insufficient due to redirects and TOCTOU. Libraries like `feedparser` that handle their own networking often lack granular security controls (like IP validation).
**Prevention:**
1. Implement a wrapper like `safe_requests_get` that disables auto-redirects (`allow_redirects=False`) and manually validates the `Location` header of every redirect against the security policy.
2. Do not pass URLs directly to `feedparser`. Fetch the content safely as bytes using the secure wrapper first, then pass the content to `feedparser.parse()`.
