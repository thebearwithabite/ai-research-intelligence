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
        pass

    if hostname.lower() in ('localhost',):
        return False

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
        return False
    except Exception:
        return False

    return True

def safe_requests_get(url: str, max_redirects: int = 5, **kwargs) -> requests.Response:
    """
    Safely performs a GET request, checking is_safe_url for every redirect.
    """
    current_url = url

    # Ensure allow_redirects is False so we can manually handle them
    kwargs['allow_redirects'] = False

    for _ in range(max_redirects + 1):
        if not is_safe_url(current_url):
            raise ValueError(f"Unsafe URL detected: {current_url}")

        response = requests.get(current_url, **kwargs)

        if response.is_redirect:
            # Clean up the previous response content if we are streaming
            # or just to be safe, though for redirects body is usually small.
            response.close()

            location = response.headers.get('Location')
            if not location:
                # Redirect without location? treat as done or error.
                # Usually shouldn't happen for is_redirect
                return response

            # Handle relative redirects
            current_url = urljoin(current_url, location)
        else:
            return response

    raise ValueError("Too many redirects")
