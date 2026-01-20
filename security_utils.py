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
    Performs a safe GET request that validates every redirect to prevent SSRF.
    Args:
        url: The URL to fetch.
        max_redirects: Maximum number of redirects to follow.
        **kwargs: Arguments to pass to requests.get (e.g. timeout, headers, stream).
    Returns:
        The final response object.
    Raises:
        ValueError: If the URL or any redirect is unsafe.
        requests.TooManyRedirects: If too many redirects.
    """
    if not is_safe_url(url):
        raise ValueError(f"Unsafe URL blocked: {url}")

    # Force allow_redirects=False to handle them manually
    kwargs['allow_redirects'] = False

    session = requests.Session()
    current_url = url
    history = []

    for _ in range(max_redirects + 1):
        response = session.get(current_url, **kwargs)

        if response.is_redirect:
            # We must close the response content if we're not returning it,
            # especially if stream=True, to free connections.
            response.close()

            location = response.headers.get('Location')
            if not location:
                # Should not happen if is_redirect is True, but strictly speaking possible
                return response

            # history logic for requests is that the history list contains the responses
            # that led to the final response.
            history.append(response)

            next_url = urljoin(current_url, location)

            if not is_safe_url(next_url):
                 raise ValueError(f"Unsafe redirect blocked: {next_url}")

            current_url = next_url

            # Remove params if they were passed in kwargs, so they don't get
            # appended again to the next request (which already has them in the URL)
            if 'params' in kwargs:
                del kwargs['params']

            continue
        else:
            # Not a redirect, return response
            response.history = history
            return response

    raise requests.TooManyRedirects(f"Exceeded maximum redirects: {max_redirects}")
