## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2024-05-24 - [SSRF via Redirects and Feed Parsing]
**Vulnerability:** The application was vulnerable to Server-Side Request Forgery (SSRF) because `requests.get` (default `allow_redirects=True`) and `feedparser.parse(url)` follow redirects automatically, potentially bypassing the initial `is_safe_url` check. This allows an attacker to redirect a request to internal services (e.g., AWS metadata 169.254.169.254) after the initial check passes.
**Learning:** Checking a URL once before request is insufficient if the client library follows redirects. Redirects must be manually inspected hop-by-hop. Additionally, libraries like `feedparser` often handle networking internally without strict security controls; fetching content safely first and passing bytes is more secure.
**Prevention:**
1. Use `allow_redirects=False` and implement a manual redirect loop that validates every `Location` header against the allowlist/blocklist.
2. Strip sensitive parameters (params, data, json) when following redirects to prevent leaking credentials.
3. Fetch content using the secure client first, then pass the response body to parsers (`feedparser`, `BeautifulSoup`).
