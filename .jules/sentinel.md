## 2024-05-23 - [SSRF Protection in Python Scrapers]
**Vulnerability:** Unrestricted URL fetching in `feedparser` and `requests` allowed potential access to local/internal network resources (SSRF).
**Learning:** Standard libraries like `requests` do not have built-in SSRF protection (blocking private IPs). Validating URLs requires checking both the initial URL and resolving the hostname to ensure it doesn't point to a private IP (DNS rebinding risk exists but basic checks help).
**Prevention:** Implement a reusable `is_safe_url` utility that checks for allowed schemes (http/https) and validates that the hostname resolves to a public IP address before making any request.
