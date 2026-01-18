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
    Performs a GET request while validating the URL and any redirects against SSRF.

    Args:
        url: The initial URL to fetch.
        max_redirects: Maximum number of redirects to follow.
        **kwargs: Additional arguments passed to requests.get.
                  Note: 'allow_redirects' is forced to False.
    """
    if not is_safe_url(url):
        raise ValueError(f"Unsafe URL: {url}")

    # Ensure we don't automatically follow redirects
    kwargs['allow_redirects'] = False

    # Extract params/data/json to only send with the first request
    params = kwargs.pop('params', None)
    data = kwargs.pop('data', None)
    json_data = kwargs.pop('json', None)

    current_url = url
    current_params = params
    current_data = data
    current_json = json_data

    history = []

    for _ in range(max_redirects + 1):
        resp = requests.get(
            current_url,
            params=current_params,
            data=current_data,
            json=current_json,
            **kwargs
        )

        # Clear sensitive data for subsequent requests (redirects)
        current_params = None
        current_data = None
        current_json = None

        if resp.is_redirect:
            location = resp.headers.get('Location')
            if not location:
                return resp

            next_url = urljoin(current_url, location)

            if not is_safe_url(next_url):
                resp.close()
                raise ValueError(f"Blocked unsafe redirect to: {next_url}")

            # Close the connection for the redirect response to avoid resource leaks
            # but keep the object for history
            resp.close()
            history.append(resp)
            current_url = next_url
            continue
        else:
            # Attach history so it looks like a normal requests response
            resp.history = history
            return resp

    raise requests.TooManyRedirects(f"Exceeded {max_redirects} redirects")
