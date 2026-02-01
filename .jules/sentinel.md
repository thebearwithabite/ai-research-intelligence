## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-02-01 - [SSRF via Redirects and Library Defaults]
**Vulnerability:** `requests.get()` follows redirects by default, allowing attackers to bypass initial IP validation (`is_safe_url`) by redirecting to a private IP (e.g., `169.254.169.254`) after the check. Additionally, `feedparser.parse(url)` performs its own insecure fetching, bypassing application-level checks entirely.
**Learning:** Checking a URL once before fetching is insufficient if the fetching library follows redirects or performs its own DNS resolution later (TOCTOU). Libraries like `feedparser` should not be trusted to fetch untrusted URLs.
**Prevention:**
1. Use a wrapper like `safe_requests_get` that disables auto-redirects (`allow_redirects=False`) and manually validates the `Location` header of every redirect.
2. For libraries like `feedparser`, fetch the content safely first (using the secure wrapper) and pass the raw content (bytes/string) to the library, rather than the URL.
