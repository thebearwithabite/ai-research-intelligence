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
    Safely makes a GET request, validating the URL and any redirects against SSRF.

    Note: This function performs a check-then-request pattern which is theoretically
    vulnerable to DNS rebinding (TOCTOU) attacks, as the DNS resolution in
    is_safe_url() may differ from the one in requests.get(). comprehensive
    protection would require a custom transport adapter or low-level socket
    manipulation, which is beyond the scope of this implementation.

    Args:
        url: The URL to request.
        max_redirects: Maximum number of redirects to follow.
        **kwargs: Arguments to pass to requests.get.

    Returns:
        requests.Response: The response object.

    Raises:
        ValueError: If a URL is unsafe.
        Exception: If max redirects exceeded.
    """
    current_url = url
    redirects_count = 0

    # We must not allow requests to handle redirects automatically
    kwargs['allow_redirects'] = False

    while redirects_count <= max_redirects:
        if not is_safe_url(current_url):
            raise ValueError(f"URL deemed unsafe: {current_url}")

        # Perform the request
        try:
            response = requests.get(current_url, **kwargs)
        except Exception as e:
            # Re-raise exceptions from requests
            raise e

        if response.is_redirect:
            redirects_count += 1
            location = response.headers.get('Location')
            if not location:
                return response

            # Handle relative redirects
            current_url = urljoin(current_url, location)

            # Security: Drop sensitive data on redirect
            # We remove params, data, json from kwargs for the next request
            # if they exist, as we shouldn't send them to the redirect target
            sensitive_keys = ['data', 'json', 'params']
            for key in sensitive_keys:
                if key in kwargs:
                    del kwargs[key]

            # Clean up the response content to avoid memory leaks if we're just following redirects
            response.close()
            continue

        else:
            return response

    raise Exception(f"Too many redirects (max {max_redirects})")
