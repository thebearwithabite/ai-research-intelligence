import ipaddress
import socket
import requests
from urllib.parse import urlparse, urljoin

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
    Safely makes a GET request, checking for SSRF at each redirect.
    """
    if not is_safe_url(url):
        raise ValueError(f"Unsafe URL: {url}")

    # We handle redirects manually to check each hop
    kwargs['allow_redirects'] = False

    current_url = url
    visited_urls = {current_url}

    for _ in range(max_redirects + 1):
        try:
            resp = requests.get(current_url, **kwargs)
        except requests.RequestException as e:
            raise e

        if resp.is_redirect:
            # It's a redirect, we must close the response to release connection if streaming
            resp.close()

            location = resp.headers.get('Location')
            if not location:
                return resp

            next_url = urljoin(current_url, location)

            if not is_safe_url(next_url):
                 raise ValueError(f"Unsafe redirect to: {next_url}")

            if next_url in visited_urls:
                raise requests.TooManyRedirects(f"Infinite redirect loop detected: {next_url}")

            visited_urls.add(next_url)
            current_url = next_url
            continue

        # Not a redirect, return the response
        return resp

    raise requests.TooManyRedirects("Exceeded maximum redirects")
