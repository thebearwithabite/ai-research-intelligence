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

def safe_requests_get(url: str, **kwargs) -> requests.Response:
    """
    Safely makes a GET request, checking for SSRF at every redirect.
    Ensures that we don't follow redirects to private IPs.
    """
    # Force allow_redirects to False so we can control it
    kwargs['allow_redirects'] = False

    # Store params/data/json for the first request only
    params = kwargs.pop('params', None)
    data = kwargs.pop('data', None)
    json_data = kwargs.pop('json', None)

    current_url = url
    history = []
    max_redirects = 30

    # Initial check
    if not is_safe_url(current_url):
        raise ValueError(f"Unsafe URL: {current_url}")

    # First request
    try:
        response = requests.get(current_url, params=params, data=data, json=json_data, **kwargs)
        history.append(response)

        while response.is_redirect:
            if len(history) > max_redirects:
                raise requests.TooManyRedirects("Too many redirects")

            location = response.headers.get('Location')
            if not location:
                break

            next_url = urljoin(response.url, location)

            if not is_safe_url(next_url):
                raise ValueError(f"Unsafe redirect to: {next_url}")

            current_url = next_url
            response = requests.get(current_url, **kwargs)
            history.append(response)

        # Reconstruct history on the final response object
        if len(history) > 1:
             response.history = history[:-1]

        return response

    except requests.exceptions.RequestException as e:
        raise e
