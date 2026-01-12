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

    # Resolve the domain to check if it points to a private IP.
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

def safe_requests_get(url: str, max_redirects=5, **kwargs):
    """
    Perform a safe GET request that checks for SSRF at every step, including redirects.
    """
    current_url = url
    redirects_followed = 0

    # Ensure allow_redirects is False so we handle them manually
    kwargs['allow_redirects'] = False

    # Store original params, data, json to only send them with the first request if needed
    # (Though typically params are in URL, data/json in body)
    # Be careful not to resend POST data on redirect if the method changes to GET
    # For this function we are strictly doing GET.

    while redirects_followed <= max_redirects:
        if not is_safe_url(current_url):
            print(f"Blocked unsafe URL: {current_url}")
            return None

        try:
            response = requests.request('GET', current_url, **kwargs)
        except Exception as e:
            print(f"Request failed: {e}")
            return None

        if response.is_redirect:
            redirect_url = response.headers.get('Location')
            if not redirect_url:
                return response

            # Handle relative redirects
            current_url = urljoin(current_url, redirect_url)
            redirects_followed += 1

            # Close the connection for the previous response if we are streaming?
            # If stream=True, we should probably close unless we are returning it.
            # But we are following redirects.
            if kwargs.get('stream'):
                 response.close()
        else:
            return response

    print("Too many redirects")
    return None
