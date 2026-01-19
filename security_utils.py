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
        return False
    except Exception:
        return False

    return True

def safe_requests_get(url: str, max_redirects=5, **kwargs) -> requests.Response:
    """
    Safely performs a GET request, validating the initial URL and any redirects
    against is_safe_url. Prevents SSRF via redirects.

    Uses a Session to persist cookies across redirects.
    """
    if not is_safe_url(url):
        raise ValueError(f"Unsafe URL: {url}")

    # We use a session to persist cookies across redirects, similar to how
    # requests.get handles them internally.
    session = requests.Session()

    # Ensure allow_redirects is False so we can check each hop
    kwargs['allow_redirects'] = False

    current_url = url
    redirects_followed = 0

    try:
        while redirects_followed <= max_redirects:
            resp = session.get(current_url, **kwargs)

            if resp.is_redirect:
                redirects_followed += 1
                location = resp.headers.get('Location')
                if not location:
                    return resp

                # Close the content for the redirect response since we're following
                resp.close()

                # Resolve relative URLs
                next_url = urljoin(current_url, location)

                # Validate the new URL
                if not is_safe_url(next_url):
                    raise ValueError(f"Redirect to unsafe URL: {next_url}")

                current_url = next_url
                continue

            return resp

        raise ValueError(f"Too many redirects (limit {max_redirects})")

    except Exception:
        session.close()
        raise
