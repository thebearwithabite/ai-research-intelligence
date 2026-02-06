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
        pass

    if hostname.lower() in ('localhost',):
        return False

    # Optional: Resolve the domain to check if it points to a private IP.
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
        # Blocking unresolved domains is safer for SSRF prevention.
        return False
    except Exception:
        return False

    return True

def safe_requests_get(url: str, max_redirects: int = 5, **kwargs) -> requests.Response:
    """
    Safely performs a GET request with SSRF protection, handling redirects manually.

    Args:
        url: The URL to fetch.
        max_redirects: Maximum number of redirects to follow.
        **kwargs: Additional arguments passed to requests.get (e.g., timeout, headers).

    Returns:
        requests.Response: The response object.

    Raises:
        ValueError: If the URL is unsafe or too many redirects occur.
        requests.RequestException: If the request fails.
    """
    # Ensure allow_redirects is False to handle them manually
    kwargs['allow_redirects'] = False

    current_url = url
    history = []

    for _ in range(max_redirects + 1):
        if not is_safe_url(current_url):
            raise ValueError(f"Unsafe URL detected: {current_url}")

        response = requests.get(current_url, **kwargs)
        history.append(response)

        if response.is_redirect:
            location = response.headers.get('Location')
            if not location:
                break

            # Handle relative redirects
            current_url = urljoin(current_url, location)

            # Close the response content if we are redirecting (unless stream is True and we want to keep it?)
            # Standard requests behavior consumes content on redirect usually, but here we just drop it.
            response.close()
        else:
            # Final response
            # Manually attach history to simulate requests behavior
            response.history = history[:-1]
            return response

    raise ValueError(f"Too many redirects (limit: {max_redirects})")
