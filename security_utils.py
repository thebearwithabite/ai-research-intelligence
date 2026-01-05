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

    # Optional: Resolve the domain to check if it points to a private IP.
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addr_info:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
            if ip.is_multicast:
                return False
    except socket.gaierror:
        # If we can't resolve it, it's safer to reject.
        return False
    except Exception:
        return False

    return True

def safe_requests_get(url, **kwargs):
    """
    Performs a requests.get with SSRF protection, validating redirects.

    Args:
        url: The URL to fetch.
        **kwargs: Arguments to pass to requests.get (e.g., timeout, headers, stream).

    Returns:
        The requests.Response object.

    Raises:
        ValueError: If the URL or any redirect is unsafe.
        Exception: If too many redirects occur.
    """
    if not is_safe_url(url):
        raise ValueError(f"Unsafe URL: {url}")

    # We must handle redirects manually to check each hop
    kwargs['allow_redirects'] = False

    # Extract custom args that requests.get doesn't understand
    redirect_limit = kwargs.pop('max_redirects', 30)

    # Start the request chain
    response = requests.get(url, **kwargs)

    history = []

    while response.is_redirect:
        response.close() # Close the previous response

        if len(history) >= redirect_limit:
             raise requests.TooManyRedirects("Too many redirects")

        location = response.headers.get('Location')
        if not location:
            break

        # Handle relative redirects
        next_url = urljoin(url, location)

        if not is_safe_url(next_url):
             raise ValueError(f"Unsafe redirect to: {next_url}")

        history.append(response)
        url = next_url # Update current URL for next iteration (important for relative redirects)

        response = requests.get(next_url, **kwargs)

    return response
