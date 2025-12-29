## 2024-05-23 - [SSRF Protection in Python Scrapers]
**Vulnerability:** Unrestricted URL fetching in `feedparser` and `requests` allowed potential access to local/internal network resources (SSRF).
**Learning:** Standard libraries like `requests` do not have built-in SSRF protection (blocking private IPs). Validating URLs requires checking both the initial URL and resolving the hostname to ensure it doesn't point to a private IP (DNS rebinding risk exists but basic checks help).
**Prevention:** Implement a reusable `is_safe_url` utility that checks for allowed schemes (http/https) and validates that the hostname resolves to a public IP address before making any request.

## 2025-05-21 - [DoS Prevention in Data Processing Handlers]
**Vulnerability:** Unbounded input parameters (`newsletters` list) and unrestricted file download sizes allowed for Resource Exhaustion (DoS). A user could supply 1000s of targets or point to a multi-gigabyte file to crash the worker via memory exhaustion.
**Learning:** "Serverless" does not mean "Infinite Resources". Handlers processing user-supplied lists or fetching external content must have strict upper bounds on iteration counts and response sizes.
**Prevention:**
1. Enforce hard limits on list inputs (e.g., max 20 items).
2. Use `stream=True` in `requests.get()` and read/check chunks to enforce a max size limit (e.g., 1MB) before parsing.
