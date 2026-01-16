## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2024-05-24 - [SSRF Bypass via HTTP Redirects]
**Vulnerability:** The application validated URLs using `is_safe_url` but then passed them to `requests.get()` (default `allow_redirects=True`) and `feedparser.parse()`. Attackers could bypass the check by providing a "safe" URL that redirects to a private IP (e.g., AWS Metadata Service `169.254.169.254`).
**Learning:** `requests.get` follows redirects by default. Validating only the initial URL is insufficient; every hop in the redirect chain must be validated. `feedparser` also handles its own transport and may follow redirects or use unsafe schemes (like `file://`) if passed a URL directly.
**Prevention:**
1. Use `allow_redirects=False` and manually handle redirects in a loop, validating `is_safe_url` for every `Location` header.
2. Never pass URLs directly to parsers like `feedparser` or `lxml`; fetch the content safely as bytes/string first, then pass the data to the parser.
