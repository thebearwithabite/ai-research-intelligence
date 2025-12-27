## 2024-05-23 - SSRF Protection via Input Validation
**Vulnerability:** The application blindly accepted URLs for RSS feeds and post scraping, allowing potential SSRF attacks against internal services (e.g., cloud metadata services).
**Learning:** `feedparser` and `requests` do not inherently validate that the destination is safe. Relying on user input for destination URLs requires strict validation.
**Prevention:** Implemented `is_safe_url` to block private IP ranges and enforce `http`/`https` schemes. Validating input at the boundary is the first line of defense.
