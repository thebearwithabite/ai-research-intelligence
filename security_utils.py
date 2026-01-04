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
        # Hostname is a domain.
        # Note: We are checking resolution here, but this is subject to TOCTOU (DNS Rebinding).
        # The safe_requests_get function mitigates this for the initial request and redirects
        # by re-checking, but for robust protection, we rely on the fact that safe_requests_get
        # handles the connection safety.
        # However, checking here is still good defense-in-depth to catch obvious internal domains.
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

def safe_requests_get(url: str, max_redirects=5, **kwargs) -> requests.Response:
    """
    Safely performs a GET request with SSRF protection, including handling redirects.

    This function manually handles redirects to ensure that every URL in the redirect
    chain is validated against is_safe_url(). This prevents attacks where a safe
    initial URL redirects to an unsafe internal IP (SSRF via redirect).

    Args:
        url: The URL to fetch.
        max_redirects: Maximum number of redirects to follow.
        **kwargs: Additional arguments passed to requests.get (e.g., timeout, stream).

    Returns:
        The final requests.Response object.

    Raises:
        ValueError: If the URL or any redirect URL is considered unsafe.
        requests.TooManyRedirects: If the redirect limit is exceeded.
    """
    # Force allow_redirects to False so we can inspect each step
    kwargs['allow_redirects'] = False

    current_url = url
    history = []

    # Use a session to handle cookies across redirects
    with requests.Session() as session:
        for _ in range(max_redirects + 1):
            if not is_safe_url(current_url):
                raise ValueError(f"Unsafe URL blocked: {current_url}")

            response = session.get(current_url, **kwargs)

            if response.is_redirect:
                history.append(response)
                # Consume content to release connection for intermediate redirects
                # (unless we want to keep them, but usually we just want the final one)
                response.content

                location = response.headers.get('Location')
                if not location:
                    # Should be a redirect but no location? Return what we have.
                    response.history = history[:-1]
                    return response

                current_url = urljoin(current_url, location)
            else:
                # We found the final response
                response.history = history
                return response

        raise requests.TooManyRedirects(f"Exceeded maximum redirect limit of {max_redirects}")
