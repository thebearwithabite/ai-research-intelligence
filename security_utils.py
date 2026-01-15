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

def safe_requests_get(url: str, max_redirects: int = 5, **kwargs) -> requests.Response:
    """
    Performs a safe GET request by manually handling redirects and validating each URL.
    This prevents SSRF attacks that bypass checks via redirects (e.g., http://safe.com -> http://localhost).

    Args:
        url: The initial URL to fetch.
        max_redirects: Maximum number of redirects to follow.
        **kwargs: Arguments passed to requests.get (e.g., timeout, headers).

    Returns:
        The final requests.Response object.

    Raises:
        ValueError: If a URL (initial or redirect) is unsafe or max redirects exceeded.
    """
    # Enforce validation on the initial URL
    if not is_safe_url(url):
        raise ValueError(f"Unsafe URL: {url}")

    # Prevent requests from automatically following redirects
    kwargs['allow_redirects'] = False

    current_url = url
    current_kwargs = kwargs.copy()

    response = None

    for _ in range(max_redirects + 1):
        try:
            response = requests.get(current_url, **current_kwargs)
        except Exception as e:
            # Rethrow or handle? Let's just let it bubble up, but maybe wrap context?
            raise e

        if response.is_redirect:
            # It's a redirect (301, 302, 303, 307, 308)
            location = response.headers.get('Location')
            if not location:
                return response

            # Close the intermediate response
            response.close()

            # Resolve relative redirects
            next_url = urljoin(current_url, location)

            if not is_safe_url(next_url):
                raise ValueError(f"Blocked redirect to unsafe URL: {next_url}")

            current_url = next_url

            # Strip params/data/json for the redirected request
            if 'params' in current_kwargs:
                del current_kwargs['params']
            if 'data' in current_kwargs:
                del current_kwargs['data']
            if 'json' in current_kwargs:
                del current_kwargs['json']

            continue

        # Not a redirect, return response
        return response

    raise ValueError(f"Too many redirects (max {max_redirects})")
