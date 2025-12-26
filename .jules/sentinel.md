## 2024-04-18 - SSRF in RSS Scrapers
**Vulnerability:** Server-Side Request Forgery (SSRF) in `extract_substack_content` and `scrape_post_content`.
**Learning:** High-level libraries like `feedparser` and `requests` follow URLs blindly. Simply checking the string URL isn't enough; we must resolve DNS to catch private IPs, though DNS rebinding remains a risk with this simple check.
**Prevention:** Always validate destination IPs against private ranges before fetching external content. Use a centralized `is_safe_url` validator.
