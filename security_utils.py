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
    Safely performs a GET request, validating every redirect against SSRF.
    This replaces requests.get() for fetching untrusted URLs.

    Args:
        url: The URL to fetch
        max_redirects: Maximum number of redirects to follow
        **kwargs: Arguments to pass to requests.get (e.g. timeout, stream, headers)

    Returns:
        requests.Response object

    Raises:
        ValueError: If the URL is unsafe or too many redirects occur
    """
    if not is_safe_url(url):
        raise ValueError(f"Unsafe URL: {url}")

    current_url = url

    # We manually handle redirects
    kwargs['allow_redirects'] = False

    for _ in range(max_redirects + 1):
        try:
            response = requests.get(current_url, **kwargs)
        except requests.RequestException as e:
            # Re-raise as is or handle? Let's propagate requests exceptions
            raise e

        if response.is_redirect:
            location = response.headers.get('Location')
            if not location:
                return response

            # Resolve relative URLs
            next_url = urljoin(current_url, location)

            if not is_safe_url(next_url):
                # We specifically block unsafe redirects here
                raise ValueError(f"Unsafe redirect to: {next_url}")

            current_url = next_url
            continue

        return response

    raise ValueError(f"Too many redirects (limit: {max_redirects})")
