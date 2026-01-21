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
    Performs a GET request with SSRF protection, validating redirects.

    Args:
        url: The URL to fetch.
        max_redirects: Maximum number of redirects to follow.
        **kwargs: Arguments to pass to requests.get (e.g., timeout, headers).

    Returns:
        requests.Response object.

    Raises:
        ValueError: If the URL is unsafe, redirects to an unsafe URL, or too many redirects.
        requests.RequestException: If the request fails.
    """
    if not is_safe_url(url):
        raise ValueError(f"Unsafe URL: {url}")

    # Ensure allow_redirects is False so we can handle them manually
    kwargs['allow_redirects'] = False

    current_url = url
    visited_urls = {url}

    # We create a copy of kwargs to avoid side effects if the caller reuses the dict
    # and to modify it for redirects (removing params/data)
    request_kwargs = kwargs.copy()

    for _ in range(max_redirects + 1):
        response = requests.get(current_url, **request_kwargs)

        if response.is_redirect:
            location = response.headers.get('Location')
            if not location:
                return response

            # Handle relative redirects
            next_url = urljoin(current_url, location)

            if not is_safe_url(next_url):
                response.close()
                raise ValueError(f"Redirect to unsafe URL: {next_url}")

            if next_url in visited_urls:
                response.close()
                raise ValueError(f"Redirect loop detected: {next_url}")

            visited_urls.add(next_url)
            current_url = next_url

            # For subsequent requests, do not send params/data/json again as they are likely
            # consumed or encoded in the redirect URL.
            if 'params' in request_kwargs: del request_kwargs['params']
            if 'data' in request_kwargs: del request_kwargs['data']
            if 'json' in request_kwargs: del request_kwargs['json']

            # Close the response body for the redirect response
            response.close()
            continue

        return response

    raise ValueError(f"Too many redirects (limit: {max_redirects})")
