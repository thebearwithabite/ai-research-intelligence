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
    Safely makes a GET request to a URL, preventing SSRF by validating
    all redirects against is_safe_url.

    Args:
        url: The URL to fetch.
        max_redirects: Maximum number of redirects to follow.
        **kwargs: Additional arguments to pass to requests.get (e.g., stream=True, timeout=10).

    Returns:
        The requests.Response object.

    Raises:
        ValueError: If the URL or any redirect is unsafe.
        requests.RequestException: If the request fails.
    """
    if not is_safe_url(url):
        raise ValueError(f"Unsafe URL blocked: {url}")

    # Force allow_redirects=False to handle them manually
    kwargs['allow_redirects'] = False

    current_url = url
    redirect_count = 0

    while True:
        response = requests.get(current_url, **kwargs)

        if response.is_redirect:
            redirect_count += 1
            if redirect_count > max_redirects:
                raise requests.TooManyRedirects(f"Exceeded max redirects ({max_redirects})")

            location = response.headers.get('Location')
            if not location:
                # Should not happen for 3xx, but handled by returning response
                return response

            # Handle relative redirects
            next_url = urljoin(current_url, location)

            if not is_safe_url(next_url):
                raise ValueError(f"Unsafe redirect blocked: {next_url}")

            # Strip Authorization header if domain changes
            next_parsed = urlparse(next_url)
            current_parsed = urlparse(current_url)
            if next_parsed.netloc != current_parsed.netloc:
                if 'headers' in kwargs and 'Authorization' in kwargs['headers']:
                    # Make a copy of headers to not mutate original kwargs permanently if they were reused (unlikely here but safe)
                    kwargs['headers'] = kwargs['headers'].copy()
                    del kwargs['headers']['Authorization']

            current_url = next_url

            # Close the connection for the redirect response
            response.close()
            continue

        return response
