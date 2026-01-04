import unittest
from unittest.mock import patch, MagicMock
import requests
import socket
from security_utils import safe_requests_get, is_safe_url

class TestSecurityUtils(unittest.TestCase):

    # --- is_safe_url tests ---

    @patch('socket.getaddrinfo')
    def test_domain_resolves_to_private_ip(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 80))
        ]
        url = "http://safe-looking-domain.com"
        self.assertFalse(is_safe_url(url), "Should reject domain resolving to private IP")

    @patch('socket.getaddrinfo')
    def test_domain_resolves_to_public_ip(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))
        ]
        url = "http://example.com"
        self.assertTrue(is_safe_url(url), "Should accept domain resolving to public IP")

    # --- safe_requests_get tests ---

    @patch('requests.Session')
    def test_safe_requests_get_no_redirect(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.__enter__.return_value = mock_session

        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response

        url = "http://example.com"
        response = safe_requests_get(url)
        self.assertEqual(response, mock_response)

    @patch('requests.Session')
    def test_safe_requests_get_safe_redirect(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.__enter__.return_value = mock_session

        response1 = MagicMock()
        response1.is_redirect = True
        response1.status_code = 302
        response1.headers = {'Location': 'http://example.com/target'}

        response2 = MagicMock()
        response2.is_redirect = False
        response2.status_code = 200

        mock_session.get.side_effect = [response1, response2]

        response = safe_requests_get("http://example.com")
        self.assertEqual(response, response2)

    @patch('requests.Session')
    def test_safe_requests_get_unsafe_redirect(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.__enter__.return_value = mock_session

        response1 = MagicMock()
        response1.is_redirect = True
        response1.status_code = 302
        response1.headers = {'Location': 'http://169.254.169.254/latest'}

        mock_session.get.return_value = response1

        with self.assertRaises(ValueError):
            safe_requests_get("http://example.com")
