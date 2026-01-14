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
        return False
    except Exception:
        return False

    return True

def safe_requests_get(url: str, max_redirects: int = 5, **kwargs) -> requests.Response:
    """
    A secure replacement for requests.get that follows redirects safely,
    validating each hop against SSRF protections (is_safe_url).

    Args:
        url: The URL to fetch
        max_redirects: Maximum number of redirects to follow
        **kwargs: Arguments passed to requests.get

    Returns:
        requests.Response: The final response object

    Raises:
        ValueError: If a URL (initial or redirect) is deemed unsafe
        requests.TooManyRedirects: If too many redirects
    """
    # Ensure we don't follow redirects automatically
    kwargs['allow_redirects'] = False

    current_url = url
    redirect_count = 0
    history = []

    while redirect_count <= max_redirects:
        # 1. Validate the URL before making the request
        if not is_safe_url(current_url):
            raise ValueError(f"Blocked unsafe URL: {current_url}")

        # 2. Make the request
        response = requests.get(current_url, **kwargs)

        # 3. Check if it's a redirect
        if response.is_redirect:
            # Important: Close the connection for the intermediate response,
            # especially if stream=True was passed.
            response.close()

            location = response.headers.get('Location')
            if not location:
                return response

            # Handle relative redirects
            current_url = urljoin(current_url, location)

            # Prepare for next iteration
            redirect_count += 1
            history.append(response)

            # Remove params/data/json from kwargs for subsequent requests
            # to prevent them from being re-sent/appended incorrectly.
            for key in ['params', 'data', 'json']:
                if key in kwargs:
                    del kwargs[key]

            continue

        # Not a redirect, return the response
        response.history = history
        return response

    raise requests.TooManyRedirects(f"Exceeded maximum of {max_redirects} redirects")
