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
        pass

    if hostname.lower() in ('localhost',):
        return False

    # Check DNS resolution
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addr_info:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
            if ip.is_multicast:
                return False
    except socket.gaierror:
        return False
    except Exception:
        return False

    return True

def safe_requests_get(url: str, max_redirects: int = 5, **kwargs) -> requests.Response:
    """
    Safely makes a GET request, strictly validating all redirects against SSRF.
    This replaces requests.get(..., allow_redirects=True).
    """
    # 1. Validate initial URL
    if not is_safe_url(url):
        raise ValueError(f"Initial URL is unsafe: {url}")

    # Force allow_redirects=False so we can manually handle them
    kwargs['allow_redirects'] = False

    current_url = url
    session = requests.Session()

    # Track history
    history = []

    for _ in range(max_redirects + 1):
        resp = session.get(current_url, **kwargs)

        if resp.is_redirect:
            # Consume content to release connection
            resp.content

            location = resp.headers.get('Location')
            if not location:
                return resp

            # Handle relative redirects
            next_url = urljoin(current_url, location)

            # 2. Validate redirect URL
            if not is_safe_url(next_url):
                raise ValueError(f"Redirection to unsafe URL blocked: {next_url}")

            history.append(resp)
            current_url = next_url

            # Only send parameters on the first request?
            # Standard requests behavior puts params in the URL for GET.
            # If 'params' was in kwargs, it's already encoded in the first URL.
            # We should clear 'params', 'data', 'json' for subsequent requests to avoid
            # re-sending them if that's not intended, though requests.get usually handles this.
            # For GET, params are in URL, so we should clear them from kwargs to avoid double encoding if we were using session.request
            # But here we are passing kwargs to session.get.
            # If we pass params={'a':1}, session.get constructs url?a=1.
            # If redirect is to url2, we call session.get(url2, params={'a':1}) -> url2?a=1.
            # This mimics requests behavior usually.
            # But let's be safe and clear body data if we were doing POST (but we are doing GET).

            continue
        else:
            resp.history = history
            return resp

    raise requests.TooManyRedirects(f"Exceeded {max_redirects} redirects")
