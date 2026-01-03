import ipaddress
import socket
import requests
from urllib.parse import urlparse, urljoin

def safe_requests_get(url: str, max_redirects: int = 5, **kwargs) -> requests.Response:
    """
    Safely performs a GET request, checking for SSRF at each redirect.
    Use this instead of requests.get() when fetching user-provided URLs.
    """
    # Enforce no auto-redirects
    kwargs['allow_redirects'] = False

    session = requests.Session()
    current_url = url

    # We maintain our own history list to emulate requests behavior
    history = []

    for _ in range(max_redirects + 1):
        if not is_safe_url(current_url):
            # Clean up potentially open sockets in history
            for resp in history:
                resp.close()
            raise ValueError(f"Unsafe URL detected: {current_url}")

        try:
            resp = session.get(current_url, **kwargs)
        except Exception:
            # Clean up history on error
            for r in history:
                r.close()
            raise

        if resp.is_redirect:
            # Consume content to release connection if we're redirecting
            # (unless stream=True was requested, but for redirects we usually want to follow)
            # Actually, requests auto-handling reads content for redirects usually.
            # Here we should read content unless we want to forward stream.
            # But typically redirects have empty bodies.
            resp.close()

            # Add to history (we need a deep copy or just the object?)
            # requests adds the response object to history.
            history.append(resp)

            location = resp.headers.get('Location')
            if not location:
                return resp

            # Handle relative redirects
            current_url = urljoin(current_url, location)
            continue
        else:
            resp.history = history
            return resp

    # Clean up
    for r in history:
        r.close()
    raise ValueError(f"Too many redirects (max {max_redirects})")

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
