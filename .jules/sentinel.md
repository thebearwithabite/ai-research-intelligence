## 2024-05-23 - [DoS Protection via Input Limits]
**Vulnerability:** Unbounded input processing in `handler.py` allowed users to specify an unlimited number of newsletters and posts, and `scrape_post_content` read full responses into memory. This created a Denial of Service (DoS) risk via resource exhaustion (CPU/Memory) and potential timeout abuse.
**Learning:** Serverless functions, while scalable, are still susceptible to application-level DoS if input processing logic is linear and unbounded. Streaming HTTP responses with size limits is crucial when fetching untrusted content to prevent memory exhaustion.
**Prevention:** Always enforce strict upper bounds on all user-supplied collection inputs (lists, counts) and use streaming with size checks for external resource fetching.
