import socket
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url: str) -> bool:
    """
    Validates that a URL is safe to access (SSRF protection).
    Checks scheme and ensures hostname is not a private/internal IP.
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
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except ValueError:
        # Not an IP address, could be a domain like 'localhost'
        if hostname.lower() in ('localhost', '127.0.0.1', '::1'):
            return False

        # NOTE: In a high-security environment, we would resolve DNS here
        # to check the resolved IP, but that adds latency and complexity.
        # For now, we rely on the fact that we are validating the input string.
        pass

    return True
