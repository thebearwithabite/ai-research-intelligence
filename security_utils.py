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

def safe_requests_get(url, max_redirects=5, **kwargs):
    """
    Safely performs a GET request, validating the URL and all redirects against SSRF.
    """
    if not is_safe_url(url):
        print(f"Blocked initial unsafe URL: {url}")
        return None

    # Force allow_redirects=False to handle them manually
    kwargs['allow_redirects'] = False

    current_url = url
    history = []

    try:
        for _ in range(max_redirects + 1):
            response = requests.get(current_url, **kwargs)

            if response.is_redirect:
                response.close() # Close connection for the redirect response
                location = response.headers.get('Location')
                if not location:
                    return response

                # Resolve relative redirects
                next_url = urljoin(current_url, location)

                if not is_safe_url(next_url):
                    print(f"Blocked redirect to unsafe URL: {next_url}")
                    return None

                history.append(response)
                current_url = next_url
                continue
            else:
                # Final response
                response.history = history
                return response

        # Too many redirects
        print(f"Too many redirects for {url}")
        return None

    except Exception as e:
        print(f"Error in safe_requests_get: {e}")
        return None
