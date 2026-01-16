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
    Safely performs a GET request, checking for SSRF at each redirect.
    """
    current_url = url
    history = []

    # Force allow_redirects to False so we can control them
    kwargs['allow_redirects'] = False

    for _ in range(max_redirects + 1):
        if not is_safe_url(current_url):
            raise ValueError(f"Security: Unsafe URL blocked: {current_url}")

        resp = requests.get(current_url, **kwargs)
        history.append(resp)

        if resp.is_redirect:
            location = resp.headers.get('Location')
            if not location:
                return resp

            # Resolve relative URLs
            next_url = urljoin(current_url, location)

            # Close previous response body if not needed (unless we want to keep history bodies?)
            # requests typically keeps them.
            resp.close()

            current_url = next_url
        else:
            # Reconstruct history
            resp.history = history[:-1]
            return resp

    raise requests.TooManyRedirects("Exceeded maximum safe redirects")
