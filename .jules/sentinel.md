## 2024-05-23 - [SSRF Protection in Python Scrapers]
**Vulnerability:** Unrestricted URL fetching in `feedparser` and `requests` allowed potential access to local/internal network resources (SSRF).
**Learning:** Standard libraries like `requests` do not have built-in SSRF protection (blocking private IPs). Validating URLs requires checking both the initial URL and resolving the hostname to ensure it doesn't point to a private IP (DNS rebinding risk exists but basic checks help).
**Prevention:** Implement a reusable `is_safe_url` utility that checks for allowed schemes (http/https) and validates that the hostname resolves to a public IP address before making any request.

## 2024-05-24 - [DoS Prevention in Scrapers]
**Vulnerability:** Unbounded inputs in scraping loop and unrestricted response fetching allowed Denial of Service via resource exhaustion (memory/CPU).
**Learning:** Python `requests.get()` loads the entire response into memory by default, which can be exploited with large files. Also, loops over user-provided lists must have upper bounds.
**Prevention:** Use `stream=True` and `iter_content` with a byte limit for fetching untrusted content. Apply strict `MAX_ITEMS` limits on all array inputs.
