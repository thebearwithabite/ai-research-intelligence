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

def safe_requests_get(url: str, max_redirects: int = 5, **kwargs) -> requests.Response:
    """
    Performs a GET request with SSRF protection, handling redirects manually.
    Validates every URL in the redirect chain.
    """
    current_url = url
    # Force disable redirects in requests to handle them manually
    kwargs['allow_redirects'] = False

    # Set a default timeout if not provided to prevent hanging
    if 'timeout' not in kwargs:
        kwargs['timeout'] = 10

    for _ in range(max_redirects + 1):
        if not is_safe_url(current_url):
            raise ValueError(f"Unsafe URL blocked: {current_url}")

        response = requests.get(current_url, **kwargs)

        if response.is_redirect:
            # It's a redirect, so we must close the response content to free connection
            response.close()

            location = response.headers.get('Location')
            if not location:
                # Redirect without location? treat as done or error.
                # requests usually returns the response if no location,
                # but is_redirect relies on status code.
                return response

            # Handle relative redirects
            current_url = urljoin(current_url, location)
            continue
        else:
            # Not a redirect, return the response
            return response

    raise ValueError(f"Too many redirects (limit {max_redirects})")
