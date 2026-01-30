import ipaddress
import socket
from urllib.parse import urlparse, urljoin
import requests
from requests.exceptions import RequestException

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
    Safe version of requests.get that prevents SSRF via redirects.
    Validates the URL and every redirect location against is_safe_url.
    """
    if not is_safe_url(url):
        raise ValueError(f"Unsafe URL: {url}")

    # Disable automatic redirects
    kwargs['allow_redirects'] = False

    current_url = url
    session = requests.Session()

    for _ in range(max_redirects + 1):
        resp = session.get(current_url, **kwargs)

        if resp.is_redirect:
            # If we are redirecting, we should close the response to free connection
            resp.close()

            location = resp.headers.get('Location')
            if not location:
                break

            # Handle relative redirects
            next_url = urljoin(current_url, location)

            if not is_safe_url(next_url):
                raise ValueError(f"Unsafe redirect to: {next_url}")

            # Prevent credential leaking on cross-origin redirects
            # If the domain changes, we should strip Authorization header if it was manually passed.
            # But implementing that fully correctly requires comparing domains.
            # For now, we assume the user of this function is aware, or we can implement a basic strip.

            # Simple strip of Authorization on domain mismatch
            original_parsed = urlparse(current_url)
            next_parsed = urlparse(next_url)

            if original_parsed.netloc != next_parsed.netloc:
                if 'headers' in kwargs and 'Authorization' in kwargs['headers']:
                    # Remove Authorization from kwargs for subsequent requests
                    # Copy headers to avoid mutating original dict if it's reused by caller
                    kwargs['headers'] = kwargs['headers'].copy()
                    del kwargs['headers']['Authorization']

            current_url = next_url
            continue

        return resp

    raise RequestException("Too many redirects")
