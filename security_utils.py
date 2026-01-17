import ipaddress
import socket
from urllib.parse import urlparse, urljoin
import requests

def is_safe_url(url: str) -> bool:
    """
    Validates a URL to prevent SSRF attacks.
    Checks if the URL scheme is http/https and if the hostname resolves to a public IP.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    if parsed.scheme not in ('http', 'https'):
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    # Check if hostname is an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
        if ip.is_multicast:
            return False
        return True
    except ValueError:
        # Hostname is a domain, we need to be careful about DNS rebinding.
        # Ideally, we would resolve here and use the IP for the request.
        # Since we can't easily patch requests/feedparser to use a specific IP without
        # complex changes, we will do a best-effort check here.
        pass

    if hostname.lower() in ('localhost',):
        return False

    # Optional: Resolve the domain to check if it points to a private IP.
    # This protects against domains configured to point to 127.0.0.1 etc.
    try:
        # valid domains can still resolve to private IPs
        addr_info = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addr_info:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
            if ip.is_multicast:
                return False
    except socket.gaierror:
        # If we can't resolve it, it's safer to reject, or accept and let the request fail.
        # Blocking unresolved domains is safer for SSRF prevention.
        return False
    except Exception:
        return False

    return True

def safe_requests_get(url, max_redirects=5, **kwargs):
    """
    Safely performs a GET request, checking for SSRF at each redirect.
    """
    current_url = url
    if not is_safe_url(current_url):
        raise ValueError(f"Unsafe URL: {current_url}")

    # We want to handle redirects manually, so force allow_redirects=False
    kwargs['allow_redirects'] = False

    # Keep track of history for the final response object if needed
    history = []

    for _ in range(max_redirects + 1):
        resp = requests.get(current_url, **kwargs)

        if resp.is_redirect:
            # Consume content to release connection
            resp.content

            location = resp.headers.get('location')
            if not location:
                return resp

            # Handle relative redirects
            next_url = urljoin(current_url, location)

            if not is_safe_url(next_url):
                 raise ValueError(f"Redirected to unsafe URL: {next_url}")

            history.append(resp)
            current_url = next_url

            # Remove data/json/params from subsequent requests if they are not meant to be repeated?
            # Usually GET requests keep params. But for safety, requests library logic on redirects:
            # - 301, 302, 303: Method becomes GET, body is dropped.
            # - 307, 308: Method and body preserved.
            # Since we are doing GET, method is GET. Body is likely None for GET.
            # Params are usually part of the URL.
            # kwargs might contain 'params' which requests adds to the URL.
            # If we pass 'params' again to the next request, and the redirect URL already has params, it might be messy.
            # Ideally, we should merge them or trust requests url construction.
            # But here we are passing `next_url` which is the full URL from Location header (resolved).
            # So we should NOT pass `params` again if they are already in the URL.
            if 'params' in kwargs:
                del kwargs['params']

            continue

        # Not a redirect, return the response
        resp.history = history
        return resp

    raise requests.TooManyRedirects("Exceeded maximum redirects")
